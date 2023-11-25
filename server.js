require("dotenv").config();
const serveStatic = require('serve-static');
const express = require("express");
const app = express();
const connectDB = require("./config/dbConnect");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const path = require("path")
const corsOptions = require("./config/corsOptions");
const PORT = process.env.PORTS || 5000;

connectDB();

// console.log(process.env.NODE_ENV);  // test

app.use(cors(corsOptions));
app.use(cookieParser());
app.use(express.json());

// app.use("/" , express.static("/" , path.join(__dirname , "public")))
// Ensure the public directory is correctly referenced here
app.use(serveStatic('D:\\back\\project-one\\API\\public'));
app.use("/", require("./routes/root"));
app.use("/auth", require("./routes/authRoutes"));
app.use("/users", require("./routes/userRoutes"));

app.all("*", (req,res)=>{
    res.status(404);
    if (req.accepts("html")) {
        res.sendFile(path.join(__dirname , "views" , "404.html"))
    } else if(req.accepts("json")) {
        res.json({message : "404 Not Found"})
    }else{
        res.type("txt").send("404 Not Found");
    }
})


mongoose.connection.once("open", () => {
  console.log("Connected by MongoDB");
  app.listen(PORT, () => {
    console.log(`server running on port ${PORT}`);
  });
});

mongoose.connection.on("error", (err) => {
  console.log(err);
});