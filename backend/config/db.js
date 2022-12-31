import mongoose from 'mongoose'

mongoose.set('strictQuery', true);
mongoose.connect(process.env.APP_CONNECT_MONGOD, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error: "));
db.once("open", function () {
    console.log("Connected successfully");
});