const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connectToDatabase = require('../models/db');
const router = express.Router();
const logger = require('../logger');

//Create JWT secret
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async(req, res, next) => {
 try {
    db = connectToDatabase('secondChance');
    collection = db.collection('users');
    const emailExists = await collection.findOne( {"email": req.body.email} );
    if (emailExists) {
        logger.error("Email already exists");
        return res.status(400).json( { error: 'Email already exists'});
    } else {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hashedPassword,
            createdAt: new Date(),
        }); 
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };
        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info("User successful created")
        res.json({ email: newUser.email, token: authtoken}); 
    }
 } catch (error) {
    return res.status(500).json( {message: 'internal server error'})
    
 }
})
module.exports = router;