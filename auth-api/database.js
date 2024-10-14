const mysql=require(mysql2/promise);
require('dotenv').config()

const pool=mysql.createpool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password:process.env.DB_PASS,
    database:process.env.DB_NAME,
});

module.exports={p00l};