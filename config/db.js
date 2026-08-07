const mysql = require("mysql2");

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false
    },
    connectTimeout: 10000
});

db.connect((err) => {
    if (err) {
        console.error(err);
    } else {
        console.log("DB 연결 성공");
    }
});

module.exports = db;