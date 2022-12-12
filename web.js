const fs = require('fs')
const express = require('express')
const app = express()
const mysql = require('mysql')
const cors = require('cors')
const db = require('./config/db')
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const https = require('https')
const port = 8001;
app.use(cors());
const http = require('http')
const { mw } = require('request-ip');
require('dotenv').config()
//passport, jwt
const jwt = require('jsonwebtoken')
const { checkLevel, logRequestResponse, isNotNullOrUndefined, namingImagesPath, nullResponse, lowLevelResponse, response, returnMoment, sendAlarm } = require('./util')
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100mb' }));
//multer
const { upload } = require('./config/multerConfig')
//express
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(mw());
// app.use(passport.initialize());
// app.use(passport.session());
// passportConfig(passport);
const schedule = require('node-schedule');

const path = require('path');
const { insertQuery, dbQueryList } = require('./query-util')
app.set('/routes', __dirname + '/routes');
app.use('/config', express.static(__dirname + '/config'));
//app.use('/image', express.static('./upload'));
app.use('/image', express.static(__dirname + '/image'));
app.use('/api', require('./routes/router'))

app.get('/', (req, res) => {
        console.log("back-end initialized")
        res.send('back-end initialized')
});
const is_test = true;

const HTTP_PORT = 8001;
const HTTPS_PORT = 8443;

if (is_test) {
        http.createServer(app).listen(HTTP_PORT, function () {
                console.log("Server on " + HTTP_PORT);
                //scheduleDaily();
        });

} else {
        const options = { // letsencrypt로 받은 인증서 경로를 입력해 줍니다.
                ca: fs.readFileSync("/etc/letsencrypt/live/daogo.co.kr/fullchain.pem"),
                key: fs.readFileSync("/etc/letsencrypt/live/daogo.co.kr/privkey.pem"),
                cert: fs.readFileSync("/etc/letsencrypt/live/daogo.co.kr/cert.pem")
        };
        https.createServer(options, app).listen(HTTPS_PORT, function () {
                console.log("Server on " + HTTPS_PORT);
                scheduleDaily();
        });
}

// Default route for server status
app.get('/', (req, res) => {
        res.json({ message: `Server is running on port ${req.secure ? HTTPS_PORT : HTTP_PORT}` });
});
// const updateSetting = async () => {
//         let money_category = ['star', 'point', 'randombox', 'esgw'];
//         let idx = 3;
//         let result = await dbQueryList(`SELECT * FROM log_${money_category[idx]}_table `);
//         result = result?.result;
//         for (var i = 0; i < result.length; i++) {
//                 if(result[i]?.explain_obj){
//                         let explain_obj = JSON.parse(result[i]?.explain_obj??"{}");
//                         console.log(explain_obj);
//                         if(explain_obj?.status){
//                                 let result_ = await insertQuery(`UPDATE log_${money_category[idx]}_table SET status=? WHERE pk=?`,[explain_obj?.status,result[i]?.pk]);
//                         }
//                 }
//         }
// }
//updateSetting();
const scheduleDaily = () => {
        schedule.scheduleJob('0 0/1 * * * *', async function () {
                let daily_data = await dbQueryList(`SELECT * FROM daily_percentage_table ORDER BY pk DESC LIMIT 1`);
                daily_data = daily_data?.result[0];
                let log_daily_initialization = await dbQueryList(`SELECT * FROM log_daily_initialization_table ORDER BY pk DESC LIMIT 1`);
                log_daily_initialization = log_daily_initialization?.result[0];
                if (returnMoment().substring(11, 16) == daily_data?.randombox_initialization_time) {
                        let user_list = await dbQueryList(`SELECT *, (SELECT SUM(price) FROM log_randombox_table WHERE user_pk=user_table.pk) AS sum_randombox FROM user_table WHERE pk NOT IN (SELECT user_pk AS pk FROM log_star_table WHERE TYPE=7 AND TIMESTAMPDIFF(second,'2022-12-07 00:00',date) > -86400) AND user_level=0`);
                        user_list = user_list?.result;
                        let user_count = user_list.length;
                        let daily_percent = await getDailyPercentReturn();

                        for (var i = 0; i < user_list.length; i++) {
                                let rand_num = Math.floor(Math.random() * 101);
                                let current_num = 0;
                                for (var idx = 0; idx < daily_percent?.money_percent?.length; idx++) {
                                        current_num += daily_percent?.money_percent[idx];
                                        if (current_num > rand_num) {
                                                break;
                                        }
                                }
                                let randombox_point = (parseFloat(daily_percent?.money[idx]) * (user_list?.sum_randombox ?? 0) / 100);
                                if (randombox_point != 0) {
                                        await insertQuery(`INSERT INTO log_randombox_table (price, user_pk, type, explain_obj) VALUES (?, ?)`, [randombox_point * (-1), user_list[i]?.pk, 6, JSON.stringify({ not_attendance: true })])
                                } else {

                                }
                        }
                        await insertQuery(`INSERT INTO log_daily_initialization_table (user_count) VALUES (?)`, [user_count]);
                }
        })
}
