require("dotenv").config();
const jsonServer = require("json-server");
const express = require("express");
const cors = require("cors");
const PORT = process.env.PORT || 4001;
const app = express();
const corsOptions = {
  origin: "*",
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true,
  allowedHeaders: "*",
  // allowedHeaders: "Content-Type,Authorization",
  maxAge: -1,
};
app.use(cors(corsOptions));
// app.options("*", cors(corsOptions));
app.use(express.json());
app.use("/api", jsonServer.defaults(), jsonServer.router("db.json"));

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
