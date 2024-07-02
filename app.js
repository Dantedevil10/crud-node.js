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

//Private Route
app.get('/user/:id', checkToken,async(req,res)=>{
    const id = req.params.id

    //Check User Exist
    const user = await User.findById(id, "-password")
    if(!user){
        return res.status(404).json({msg:'Usuario Nao Encontrado'})
    }
    res.status(200).json(user)
})

//
function checkToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg:"Acesso Negado"})
    }
    try{
        const secret = process.env.SECRET
        jwt.verify(token, secret)

        next()
    }catch(err){
        res.status(400).json({msg:"Token Invalido"})
    }
}
//

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
    const passwordHash = await bcrypt.hash(password, salt)

    //Create User
    const user = new User({
        name,
        email,
        password: passwordHash
    })
    try{
        await user.save()
        res.status(201).json({msg:'Usuario Criado Com Sucesso'})
    }   
    catch(err){
        console.log(err)
        res.status(500).json({msg:'Erro No Servidor Tente Mais Tarde'})
    }
})

//Login User
app.post('/auth/login',async(req,res)=>{
    const {email,password} = req.body

    //Validations
    if(!email){
        return res.status(422).json({msg:'Email é Obrigatorio'})
    }
    if(!password){
        return res.status(422).json({msg:'Senha é Obrigatorio'})
    }
    //Check user Exist
    const user = await User.findOne({email:email})
    if(!user){
        return res.status(404).json({msg: 'Usuario Nao Encontrado!'})
    }
    //Check Password Match
    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(422).json({msg:'Senha Invalida'})
    }
    try{
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user.id,
        },secret)

        res.status(200).json({msg:'Autenticação Realizada Com Sucesso', token})
    }
    catch(err){
        console.log(err)
        res.status(500).json({msg:'Erro No Servidor Tente Mais Tarde'})
    }
})


//Credencials 
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS


mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.8baj1l4.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`).then(()=>{
    app.listen(3000)
    console.log('Foi')

}).catch((err)=>console.log(err))

