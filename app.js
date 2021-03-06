const express = require('express')
const config = require('config')
const mongoose = require('mongoose')

const app = express()

const PORT = config.get('port') || 5000

async function start(){
    try {
        await mongoose.connect(config.get('mongoUri'),{
            userNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true

        })
    } catch(e){
        console.log('Server Error', e.message)
        process.exit(1)
    }
}

start()


app.listen(5000, () => console.log(`App has been started on port ${PORT}...`))