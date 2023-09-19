const mongoose = require('mongoose');
mongoose.set('strictQuery', false);

//connecting mongoose with database
mongoose.set('strictQuery', false);
const connectToMongo = async () => {
    const connectdb = await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
        .then(() => { console.log("Connected to MongoDB Successfully") })
        .catch((error) => { console.log('Database not connected successfully') })
}

module.exports = connectToMongo;