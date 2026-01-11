
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRECT);


dotenv.config();

const app = express();
app.use(
  cors({
    origin: [
      "http://localhost:5173",process.env.SITE_DOMAIN
      ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept'
    ],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    preflightContinue: false,
    optionsSuccessStatus: 204
  })
);
app.use(express.json());

const PORT = 3000;

const admin = require("firebase-admin");

const serviceAccount = require("./loanlink-89b1f-firebase-adminsdk.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const verifyFBtoken = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const idToken = token.split(" ")[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    console.log(decodedToken);
    req.decoded_email = decodedToken.email;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// 3. Define a route for the root URL
async function run() {
  try {
    // Connect the client to the server
    const db = client.db("loanlink");
    const allLoan = db.collection("all-loan");
    const loanCategory = db.collection("Loan-Category");
    const usersCollection = db.collection("users");
    const Payments = db.collection("payments");
    // Admin middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await usersCollection.findOne(query);

      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "forbidden" });
      }
      next();
    };

    // Manager middleware
    const verifyManager = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await usersCollection.findOne(query);

      if (!user || user.role !== "manager") {
        return res.status(403).send({ message: "forbidden" });
      }
      next();
    };
    // Borrower middleware
    const verifyBorrower = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await usersCollection.findOne(query);
      console.log(user.role);
      if (!user || user.role !== "borrower") {
        return res.status(403).send({ message: "forbidden" });
      }
      next();
    };

    // Add login user data in users collection
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;
        // Check if user with same email already exists
        const existingUser = await usersCollection.findOne({
          email: user.email,
        });
        if (existingUser) {
          return res
            .status(409)
            .json({ message: "User already exists with this email" });
        }
        const result = await usersCollection.insertOne(user);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    //get all users
    app.get("/all-users", verifyFBtoken, verifyAdmin, async (req, res) => {
      try {
        const users = await usersCollection.find().toArray();
        res.json(users);
      } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Get user by email
    app.get("/user-data", verifyFBtoken, async (req, res) => {
      try {
        const email = req.query.email;
        if (!email)
          return res
            .status(400)
            .json({ message: "Missing email query parameter" });

        if (email !== req.decoded_email) {
          return res.status(403).json({ message: "Unauthoried Access" });
        }

        const query = { $or: [{ email }, { userEmail: email }] };
        const userData = await usersCollection.find(query).toArray();
        res.json(userData);
      } catch (error) {
        console.error("Error fetching user loans:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    //get user data by id
    app.get("/user/:id", verifyFBtoken, verifyAdmin, async (req, res) => {
      try {
        const { ObjectId } = require("mongodb");
        const id = req.params.id;
        if (!ObjectId.isValid(id))
          return res.status(400).json({ message: "Invalid user ID" });
        const query = { _id: new ObjectId(id) };
        const user = await usersCollection.findOne(query);
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json(user);
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );

    // Add a new loan by users or borrowers
    app.post("/add-loan", verifyFBtoken, verifyBorrower, async (req, res) => {
      try {
        const newLoan = req.body;
        const result = await allLoan.insertOne(newLoan);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // Add a new loan category by Manager
    app.post(
      "/dashboard/add-loan-category",
      verifyFBtoken,
      verifyManager,
      async (req, res) => {
        try {
          const newLoanCategory = req.body;
          const result = await loanCategory.insertOne(newLoanCategory);
          res.send(result);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
    );
    // Update loan category by admin and manager
    app.patch("/update-loan-category/:id", verifyFBtoken, async (req, res) => {
      try {
        const { ObjectId } = require("mongodb");
        const id = req.params.id;
        const updatedData = req.body;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid category ID" });
        }
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: updatedData,
        };
        const result = await loanCategory.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // Update user roleStatus by admin
    app.patch(
      "/update-roleStatus/:id",
      verifyFBtoken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { ObjectId } = require("mongodb");
          const id = req.params.id;

          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid user ID" });
          }

          const { roleStatus, suspendInfo } = req.body;

          if (!["Approved", "Suspended"].includes(roleStatus)) {
            return res.status(400).json({
              message: "Invalid roleStatus value",
            });
          }

          const updateDoc = {
            roleStatus,
          };

          // If Suspended → require reason & feedback
          if (roleStatus === "Suspended") {
            if (!suspendInfo?.reason || !suspendInfo?.feedback) {
              return res.status(400).json({
                message: "Suspend reason and feedback are required",
              });
            }

            updateDoc.suspendInfo = {
              reason: suspendInfo.reason,
              feedback: suspendInfo.feedback,
              suspendedAt: new Date(),
            };
          }

          // If Approved → clear suspension info
          if (roleStatus === "Approved") {
            updateDoc.suspendInfo = null;
          }

          const result = await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateDoc }
          );

          res.send({
            success: true,
            modifiedCount: result.modifiedCount,
          });
        } catch (error) {
          res.status(500).json({
            message: "Failed to update user roleStatus",
            error: error.message,
          });
        }
      }
    );

    // Update loan category by manager
    app.patch("/update-loan-category/:id", verifyFBtoken, async (req, res) => {
      try {
        const { ObjectId } = require("mongodb");
        const id = req.params.id;
        const updatedData = req.body;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid category ID" });
        }
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: updatedData,
        };
        const result = await loanCategory.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // Delete loan category by admin
    app.delete("/delete-loan-category/:id", verifyFBtoken, async (req, res) => {
      try {
        const { ObjectId } = require("mongodb");
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid category ID" });
        }
        const filter = { _id: new ObjectId(id) };
        const result = await loanCategory.deleteOne(filter);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Update loan status by manager
    app.patch("/update-loan/:id", verifyFBtoken, async (req, res) => {
      try {
        const { ObjectId } = require("mongodb");
        const id = req.params.id;
        const updatedStatus = req.body.status;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid loan ID" });
        }
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: { status: updatedStatus },
        };
        const result = await allLoan.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    //payment related apis
    app.post(
      "/create-checkout-session",
      verifyFBtoken,
      verifyBorrower,
      async (req, res) => {
        try {
          const { cost, loanID } = req.body;

          const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            line_items: [
              {
                price_data: {
                  currency: "usd",
                  product_data: {
                    name: "Loan Application Fee",
                  },
                  unit_amount: cost * 100, // $10 -> 1000 cents
                },
                quantity: 1,
              },
            ],
            mode: "payment",
            // Metadata allows you to find this loan again after payment
            metadata: { loanId: loanID },
            success_url: `${process.env.SITE_DOMAIN}/dashboard/payments-success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payments-cancel`,
          });

          // Send the URL as JSON so React can redirect
          res.json({ url: session.url });
        } catch (error) {
          console.error(error);
          res.status(500).send({ error: error.message });
        }
      }
    );

    app.patch(
      "/payments-success",
      verifyFBtoken,
      verifyBorrower,
      async (req, res) => {
        try {
          const sessionId = req.query.session_id;
          const session = await stripe.checkout.sessions.retrieve(sessionId);

          const transactionID = session.payment_intent;

          const query = {
            transactionID: transactionID,
          };

          const paymentExist = await Payments.findOne(query);

          if (paymentExist) {
            return res.send({ message: "Already Exist", transactionID });
          }

          if (session.payment_status === "paid") {
            const id = session.metadata.loanId;

            const query = { _id: new ObjectId(id) };
            const update = { $set: { paymentStatus: "Paid" } };
            const result = await allLoan.updateOne(query, update);

            const payment = {
              amount: session.amount_total / 100,
              customerEmail: session.customer_details.email,
              loanID: id,
              transactionID: session.payment_intent,
              paymentStatus: session.payment_status,
              paidAt: new Date(),
            };

            const resultPayment = await Payments.insertOne(payment);

            return res.send({
              success: true,
              modifyLoan: result,
              paymentinfo: resultPayment,
            });
          } else {
            return res
              .status(400)
              .send({ success: false, message: "Payment not verified" });
          }
        } catch (error) {
          console.error("Database Error:", error);
          res.status(500).send({ success: false, error: error.message });
        }
      }
    );

    // loan category data change by admin
    app.patch("/update-loan-category/:id", verifyFBtoken, async (req, res) => {
      try {
        const { ObjectId } = require("mongodb");
        const id = req.params.id;
        const updatedData = req.body;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid category ID" });
        }
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: updatedData,
        };
        const result = await loanCategory.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    //get all loans
    app.get("/all-loan", verifyFBtoken, async (req, res) => {
      try {
        const email = req.query.email;
        const filter = email ? { $or: [{ email }, { userEmail: email }] } : {};
        const loan = await allLoan.find(filter).toArray();
        res.json(loan);
      } catch (error) {
        console.error("Error fetching loans:", error);
        res.status(500).json({ message: error.message });
      }
    });
    //get all loans
    app.get("/all-loans", verifyFBtoken, async (req, res) => {
      try {
 
        const loan = await allLoan.find().toArray();
        res.json(loan);
      } catch (error) {
        console.error("Error fetching loans:", error);
        res.status(500).json({ message: error.message });
      }
    });

    //get loans by status aproved
    app.get(
      "/approved-loan",
      verifyFBtoken,
      verifyManager,
      async (req, res) => {
        try {
          const query = { status: "Approved" };
          const approvedLoan = await allLoan.find(query).toArray();
          res.send(approvedLoan);
        } catch (error) {
          console.error("Error fetching approved loans:", error);
          res.status(500).json({ message: "Internal server error" });
        }
      }
    );
    //user cancel loan request
    app.delete(
      "/cancel-loan/:id",
      verifyFBtoken,
      verifyBorrower,
      async (req, res) => {
        try {
          const { ObjectId } = require("mongodb");
          const id = req.params.id;
          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid loan ID" });
          }
          const filter = { _id: new ObjectId(id) };
          const result = await allLoan.deleteOne(filter);
          res.send(result);
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      }
    );

    // get loan by email (specific user)
    app.get("/my-loan", async (req, res) => {
      try {
        const email = req.query.email;
        if (!email)
          return res
            .status(400)
            .json({ message: "Missing email query parameter" });

        const query = { $or: [{ email }, { userEmail: email }] };
        const myLoan = await allLoan.find(query).toArray();
        res.json(myLoan);
      } catch (error) {
        console.error("Error fetching user loans:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });
    // get payment hsitory by email (specific user)
    app.get("/my-payments", verifyFBtoken, async (req, res) => {
      try {
        const email = req.query.email;
        if (!email)
          return res
            .status(400)
            .json({ message: "Missing email query parameter" });

        if (email !== req.decoded_email) {
          return res.status(403).json({ message: "Forbidden Access" });
        }

        const query = { $or: [{ email }, { customerEmail: email }] };

        // console.log('headers',req.headers)
        const myPayments = await Payments.find(query).toArray();
        res.json(myPayments);
      } catch (error) {
        console.error("Error fetching user loans:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    //get loan by status pending
    app.get("/pending-loan", verifyFBtoken, verifyManager, async (req, res) => {
      try {
        const query = { status: "Pending" };
        const pendingLoan = await allLoan.find(query).toArray();
        res.send(pendingLoan);
      } catch (error) {
        console.error("Error fetching pending loans:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });
    // get loan by id
    app.get("/loan/:id", async (req, res) => {
      try {
        const { ObjectId } = require("mongodb");
        const id = req.params.id;
        if (!ObjectId.isValid(id))
          return res.status(400).json({ message: "Invalid loan ID" });

        const query = { _id: new ObjectId(id) };
        const loan = await loanCategory.findOne(query); // <-- changed to allLoan

        if (!loan) return res.status(404).json({ message: "Loan not found" });
        res.json(loan);
      } catch (error) {
        console.error("Error fetching loan:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Get loan categories by limit
    app.get("/loan-category", async (req, res) => {
      try {
        const categories = await loanCategory
          .find({ showOnHome: true })
          .limit(6)
          .toArray();

        res.json(categories || []);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // Get loan categories
    app.get("/all-loan-category", async (req, res) => {
      try {
        const categories = await loanCategory.find().toArray();
        res.json(categories) || [];
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    app.get("/", (req, res) => {
      res.send("Hello from the LoanLink Backend!");
    });

    // Start the server AFTER MongoDB is connected
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error);
    process.exit(1);
  }
}

run().catch(console.dir);
