// imports
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//Config JsonResponse
app.use(express.json())

//Models
const User = require('./models/User') 

//Public Route
app.get('/',(req,res)=>{
    res.status(200).json({msg:'Bem Vindo a Essa Poraa'})
})

//User Register
app.post('/auth/register',async(req,res)=>{
    const {name,email,password,confirmpassword} = req.body

    //validations
    if(!name){
        return res.status(422).json({msg:'Nome é Obrigatorio'})
    }
    if(!email){
        return res.status(422).json({msg:'Email é Obrigatorio'})
    }
    if(!password){
        return res.status(422).json({msg:'Senha é Obrigatorio'})
    }
    if(password !== confirmpassword){
        return res.status(422).json({msg:'Emails Não Iguais'})
    }

    //Check User Exist
    const userExist = await User.findOne({email:email})
    if(userExist){
        return res.status(422).json({msg: 'Por Favor, utilize outro e-mail!'})
    }
    //Create Password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash()
})


//Credencials 
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS


mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.8baj1l4.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`).then(()=>{
    app.listen(3000)
    console.log('Foi')

}).catch((err)=>console.log(err))

