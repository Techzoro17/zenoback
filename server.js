const express = require('express');
const app = express();
const Fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userdata = require('./data/user.json');
const orders = require('./data/Orders.json');
require('dotenv').config();


const PORT = 3500;

//Middle Ware 
app.use(cors());
app.use(express.json());

//Api Routes

app.post('/register',async(req,res)=>{

    try {
     const user = req.body;
     
     if (!user.username || !user.password) {
        return res.status(400).json({ message: "Username and password are required" });
      }

     const fetched = await Fs.readFile(path.join(__dirname,'data','user.json'),'utf-8');
     const parsed = await JSON.parse(fetched);
     const hashedpass =await bcryptjs.hash(user.password,10);
     const newuser = {username:user.username,password:hashedpass,user_id:user.user_id};
     parsed.push(newuser);
     await Fs.writeFile(path.join(__dirname,'data','user.json'),JSON.stringify(parsed,null,2),'utf-8');
     res.status(201).json(parsed);
     
    } catch (error) {
     console.log(error)
     res.status(404).json({message:"Can't create"});
    }
 
 })
 

 app.post('/login',async(req,res)=>{

     const user = req.body.username;
     const password = req.body.password;
     const fetched = await Fs.readFile(path.join(__dirname,'data','user.json'),'utf-8');
     const parsed = await JSON.parse(fetched);
     const founduser = parsed.find((data)=>data.username===user);
     if(!user || !password){
      return   res.status(400).json({message:"Credentials are required"});
     }

     if(!founduser){
       return res.sendStatus(401);
     }
     console.log(founduser);

    const match = await bcryptjs.compare(password,founduser.password);
    console.log(match);

    if( match){
      
        const accesstoken = jwt.sign({username:founduser.username},process.env.access_key,{expiresIn:'1h'});

        const refreshtoken = jwt.sign({username:founduser.username},process.env.access_key,{expiresIn:'1h'});
        
        const currentuser = {...founduser,refreshtoken,accesstoken};

        const others = parsed.filter((item)=>item.username!=founduser.username);

        const updated =[...others,currentuser];
        await Fs.writeFile(path.join(__dirname,'data','user.json'),JSON.stringify(updated,null,2),'utf-8');
        
        res.cookie('jwt',refreshtoken,{httpOnly:true,maxAge:24*60*60*1000});
        res.json({accesstoken});
    }else{
        res.sendStatus(401);
    }
       
 })
 
 const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.sendStatus(401); // Unauthorized if no token is provided
    }

    // Assumes the token is passed as `Bearer <token>`
    jwt.verify(authHeader, process.env.access_key, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Forbidden if token is invalid
        }
        req.user = user; // Attach the decoded token payload to `req.user`
        next();
    });
};

 app.get('/resdata',verifyToken, async(req,res)=>{
    try {

        const fetched =  await Fs.readFile(path.join(__dirname,'data','restaurent.json'),'utf-8');
        const jsondata = await JSON.parse(fetched);
        res.status(201).json(jsondata);
    } catch (error) {
        res.status(404).json({message:"No Data found"});
    }
})

app.get('/user/:id', async(req,res)=>{

    try {
     const userId = req.params.id;
     

    jwt.verify(userId,process.env.access_key, (err, decoded) => {
        if (err) {
            console.log('Invalid token:', err.message);
        } else {
            const filter = userdata.find((item)=>item.username===decoded.username);
            res.status(200).json(filter);
        }
    });

    

    // res.status(200).json
    } catch (error) {
      console.log(error);
    }

 })
 
app.get('/order', async(req,res)=>{
    const fetched = await Fs.readFile(path.join(__dirname,'data','Orders.json'),'utf-8');
    const parsed = await JSON.parse(fetched);
    res.status(200).json(parsed);
})

app.post('/order',async(req,res)=>{
    try {
        const item = req.body.order;

        const fetched = await Fs.readFile(path.join(__dirname,'data','Orders.json'),'utf-8');
        const parsed = await JSON.parse(fetched);
        parsed.push(item);
        await Fs.writeFile(path.join(__dirname,'data','Orders.json'),JSON.stringify(parsed,null,2),'utf-8');
        res.status(201).json(parsed);
        
    } catch (error) {
        res.sendStatus(202);
        
    }

})



app.listen(PORT,()=>{
    console.log(`Your App is runnning on port: ${PORT} `);
})