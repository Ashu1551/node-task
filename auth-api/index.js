const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bodyparser =require('body-parser');
const{pool}= require('./database');
require('dotenv').config();

const app = express();
app.use(bodyparser.json());

const JWT_SECRET =process.env.JWT_SECRET;
const sendEmail=async (to,subject,text)=>{
    const transporter=nodemailer.createTransport({
        service:'gmail',
        auth:{
            user:process.env.EMAIL_USER,
            pass:process.env.EMAIL_PASS,

        },
    });
    await transporter.sendMail({from:process.env.EMAIL_USER,to,subject,text });
};
app.post('/signup',async(req,res)=>{
    const{firstName,lasName,email,password}=req.body;
    const hashedPassword=await bcrypt.hash(password,10);
    try{
        const [user]=await pool.query('SELECT*FROM users WHERE email =?',[email]);
        if(user.length) return res.status(400).strictContentLength({message:'Email already  exists.'});

        await pool.query(
            'INSERT INTO users (first_name,last_name,email,password) VALUES(?,?,?,?)',
            [firstName,lasName,email,hashedPassword]
        );
        res.status(201).json({message:'user registered successfully'});

    }catch(error){
        res.status(500).json({message:'Error registering user.'});
    }
});
app.post('/login',async(req,res)=>{
    const {email,password}=req.body;
    try{
        const[user]= await pool.query('SELECT * FROMusers WHERE email =?[email');
        if(!user.length) return res.status(404).json({message: 'user not found.'    });
        const isValid =await bcrypt.compare(password,user[0].password);
        if(!isValid) return res.status(401).json({message:'Invalid credentials.'});

        const token=jwt.sign({id:user[0].id},JWT_SECRET,{expresIn:'1H'});
        res.json({token});
    }catch (error){
        res.status(500).json({message:'Error logging in.'});

    }
});
app.get('/user',async(req,res)=>{
    const token=req.headers.authorization?.split('')[1];
    try{
        const decoded = jwt.verify(token,JWT_SECRET);
        const [user]=await pool.query('SELECT id,first_name,email FROM users WHERE id=?',[decoded.id]);

        res.json(user[0]);
    }catch(error){
        res.status(401).json({message:'Invalid token.'});
    }
 });
 app.post('/forget-password',async(req,res)=>{
    const {email}=req.body;

    try{
        const [user]=await poolQuery('SELECT * FROM users WHERE email=?',[email]);
        if(!user.length)return res.status(400).json({message:'User not found'});
        const token =jwt.sign({id:user[0].id},JWT_SECRET,{expresIn:'5m'});
        const resetLink='${process.env.FRONTEND_URL}/reset-password/${token}';

        await sendEmail(email,'Password Reset','Click here to reset your password:${resetLink}');
        res.json({message:'Password reset link sent to your email.'});
    }catch (error){
        res.status(500).json({message:'Error sending password reset link.'});
    }
 });

 app.post('/reset-password/:token',async(req,res)=>{
    const {token}=req.params;
    const{ newPassword,confirmPassword}=req.body;

    if(newPassword !==confirmPassword){
        return res.status(400).json({message:'Passwords do not match'});

    }
    try{
        const decoded=jwt.verify(token,JWT_SECRET);
        const hashedPassword= await bcrypt.hash(newPassword,10);

        await pool.query('UPDATE users SET password =? WHERE id=?',[hashedPassword,decoded.id]);
        res.json({message:'Password Updated Successfully.'});

    }catch (error){
        res.status(400).json({message:'Invalid or expired token '});
    }
 });
 const PORT =process.env.PORT || 3000;
 app.listen(PORT,()=> console.log('Server running on port ${PORT}'));
