// 1. Import the Express module
const express = require('express');
const cors = require("cors");
const dotenv = require("dotenv");
const { MongoClient, ServerApiVersion } = require('mongodb');
// 2. Initialize the Express application
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());



const PORT = 3000;

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


   // Add login user data in users collection
   app.post("/users", async (req, res) => {
    try {
      const user = req.body;
      const result = await usersCollection.insertOne(user);
      res.send(result);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  });
    
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
    
    // Add a new loan by users or borrowers
    app.post("/add-loan", async (req, res) => {
      try {
        const newLoan = req.body;
        const result = await allLoan.insertOne(newLoan);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // Add a new loan category by admin
    app.post("dashboard/add-loan-category", async (req, res) => {
      try {
        const newLoanCategory = req.body;
        const result = await loanCategory.insertOne(newLoanCategory);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
    // Update loan category by admin
    app.patch("/update-loan-category/:id", async (req, res) => {
      try {
        const { ObjectId } = require('mongodb');
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
    app.delete("/delete-loan-category/:id", async (req, res) => {
      try {
        const { ObjectId } = require('mongodb');
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
    // Update loan status by admin
    app.patch("/update-loan/:id", async (req, res) => {
      try {
        const { ObjectId } = require('mongodb');
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
//get all loans
    app.get("/all-loan", async (req, res) => {
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

    //get loans by status aproved
    app.get("/approved-loan", async (req, res) => {
      try {
        const query = { status: "Approved" };
        const approvedLoan = await allLoan.find(query).toArray();
        res.send(approvedLoan);
      } catch (error) {
        console.error("Error fetching approved loans:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });
    //user cancel loan request
    app.delete("/cancel-loan/:id", async (req, res) => {
      try {
        const { ObjectId } = require('mongodb');
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
    });

// get loan by email (specific user)
app.get("/my-loan", async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).json({ message: "Missing email query parameter" });

    const query = { $or: [{ email }, { userEmail: email }] };
    const myLoan = await allLoan.find(query).toArray();
    res.json(myLoan);
  } catch (error) {
    console.error("Error fetching user loans:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

    //get loan by status pending
    app.get("/pending-loan", async (req, res) => {
      try {
        const query = { status: "Pending" };
        const pendingLoan = await loanCategory.find(query).toArray();
        res.send(pendingLoan);
      } catch (error) {
        console.error("Error fetching pending loans:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });
// get loan by id
app.get("/loan/:id", async (req, res) => {
  try {
    const { ObjectId } = require('mongodb');
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid loan ID" });

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
        const categories = await loanCategory.find().limit(6).toArray();
        res.json(categories) || [];
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
    app.get('/', (req, res) => {
      res.send('Hello from the LoanLink Backend!');
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