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
    
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
    
    // Define routes AFTER connection
    app.post("/add-loan", async (req, res) => {
      try {
        const newLoan = req.body;
        const result = await allLoan.insertOne(newLoan);
        res.send(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });
//get all loans
    app.get("/all-loan", async (req, res) => {
      try {
        const loan = await allLoan.find().toArray();
        res.json(loan) || [];
        console.log(loan);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

// get loan by email
 app.get("/my-loan", async (req, res) => {
      try {
        const userEmail = req.query.email;
        const query = { email: userEmail };
        const myLoan = await allLoan.find(query).toArray();
        res.send(myLoan);
      } catch (error) {
        console.error("Error fetching favorite:", error);
        res.status(500).json({ message: "Internal server error" });
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