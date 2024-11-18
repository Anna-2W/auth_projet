const express = require('express');
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express();
const mongoose = require("mongoose");

const authRouter = require("./routers/authRouter");
mongoose.connect(process.env.MONGO_URI).then(() => {
    console.log("Connected to MongoDB...");
}).catch((err) => {
    console.error(err);
})

app.use(express.json());
app.use(cors())
app.use(helmet())
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }))
app.use('/api/auth', authRouter);
app.get('/', (req, res) => {
    res.json('Hello World!--');
})

app.listen(process.env.PORT, () => {
    console.log(`Server started on port ${process.env.PORT}`);
});