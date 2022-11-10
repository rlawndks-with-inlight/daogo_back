const mysql = require('mysql')

const db = mysql.createConnection({
    host : "211.45.162.239",
    user : 'root',
    password : 'qjfwk100djr!',
    port : 3306,
    database:'daogo',
    timezone: 'Asia/Seoul',
    charset: 'utf8mb4'
})
db.connect();

module.exports = db;