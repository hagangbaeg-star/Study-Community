const mysql = require("mysql2");

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "1101",
    database: "studycommunity"
});

db.connect((err) => {
    if (err) {
        console.log("DB 연결 실패");
        console.log(err);
    } else {
        console.log("DB 연결 성공");
    }
});

module.exports = db;