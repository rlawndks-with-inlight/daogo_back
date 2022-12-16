//const { request } = require('express')
const jwt = require('jsonwebtoken')
const db = require('./config/db')
const jwtSecret = "djfudnsqlalfKeyFmfRkwu"
const firebase = require("firebase-admin");
const fcmNode = require("fcm-node");
const serviceAccount = require("./config/privatekey_firebase.json");
const { insertQuery, dbQueryList } = require('./query-util');
const when = require('when')
var ip = require('ip');
const requestIp = require('request-ip');
const firebaseToken = 'fV0vRpDpTfCnY_VggFEgN7:APA91bHdHP6ilBpe9Wos5Y72SXFka2uAM3luANewGuw7Bx2XGnvUNjK5e5k945xwcXpW8NNei3LEaBtKT2_2A6naix8Wg5heVik8O2Aop_fu8bUibnGxuCe3RLQDtHNrMeC5gmgGRoVh';
const fcmServerKey = "AAAA35TttWk:APA91bGLGZjdD2fgaPRh8eYyu9CDSndD97ZdO4MBypbpICClEwMADAJnt2giOaCWRvMldof5DkplMptbmyN0Fm0Q975dm-CD7i0XhrHzjgMN0EKfXHxLy4NyohEVXDHW5DBfYrlncvQh";
firebase.initializeApp({
    credential: firebase.credential.cert(serviceAccount)
});
const sendAlarm = (title, note, table, pk, url) => {
    let fcm = new fcmNode(fcmServerKey)
    let message = {
        to: '/topics/' + 'weare',
        "click_action": "FLUTTER_NOTIFICATION_CLICK",
        "priority": "high",
        notification: {
            title: title,
            body: note,
            url: url ?? '/',
            click_action: "FLUTTER_NOTIFICATION_CLICK",
            badge: "1",
            "sound": "default"
        },
        data: {
            table: table,
            pk: pk.toString(),
            url: url ?? '/',
            title: title,
            body: note,
        }
    }
    //const options = { priority: 'high', timeToLive: 60 * 60 * 24 };
    fcm.send(message, (err, res) => {
        if (err) {
            console.log("Error sending message:", err);
        } else {
            console.log("Successfully sent message:", res);
        }
    })
}

let checkLevel = (token, level) => {
    try {
        if (token == undefined)
            return false

        //const decoded = jwt.decode(token)
        const decoded = jwt.verify(token, jwtSecret, (err, decoded) => {
            //console.log(decoded)
            if (err) {
                console.log("token이 변조되었습니다." + err);
                return false
            }
            else return decoded;
        })
        const user_level = decoded.user_level

        if (level > user_level)
            return false
        else
            return decoded
    }
    catch (err) {
        console.log(err)
        return false
    }
}
const formatPhoneNumber = (input) => {
    const cleanInput = input.replaceAll(/[^0-9]/g, "");
    let result = "";
    const length = cleanInput.length;
    if (length === 8) {
        result = cleanInput.replace(/(\d{4})(\d{4})/, '$1-$2');
    } else if (cleanInput.startsWith("02") && (length === 9 || length === 10)) {
        result = cleanInput.replace(/(\d{2})(\d{3,4})(\d{4})/, '$1-$2-$3');
    } else if (!cleanInput.startsWith("02") && (length === 10 || length === 11)) {
        result = cleanInput.replace(/(\d{3})(\d{3,4})(\d{4})/, '$1-$2-$3');
    } else {
        result = undefined;
    }
    return result;
}
const categoryToNumber = (str) => {
    if (str == 'oneword') {
        return 0;
    } else if (str == 'oneevent') {
        return 1;
    } else if (str == 'theme') {
        return 2;
    } else if (str == 'strategy') {
        return 3;
    } else if (str == 'issue') {
        return 4;
    } else if (str == 'feature') {
        return 5;
    } else if (str == 'video') {
        return 6;
    } else {
        return -1;
    }
}
const lowLevelException = {
    code: 403,
    message: "권한이 없습니다."
}
const nullRequestParamsOrBody = {
    code: 400,
    message: "입력이 잘못되었습니다.(요청 데이터 확인)"
}

const logRequestResponse = (req, res) => {

    let requestIp;
    try {
        requestIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '0.0.0.0'
    } catch (err) {
        requestIp = '0.0.0.0'
    }
    requestIp = ip.address();
    let request = {
        url: req.originalUrl,
        headers: req.headers,
        query: req.query,
        params: req.params,
        body: req.body,
        file: req.file || req.files || null
    }
    request = JSON.stringify(request)
    let response = JSON.stringify(res)
    // console.log(request)
    console.log(response)
    const decode = checkLevel(req.cookies.token, 0)
    let user_pk = 0;
    let user_id = "";
    if (decode) {
        user_pk = decode.pk;
        user_id = decode.id;
    } else {
        user_pk = -1;
    }
    db.query(
        "INSERT INTO log_table (request, response, response_result, response_message, request_ip, user_id, user_pk) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [request, response, res?.result, res?.message, requestIp, user_id, user_pk],
        (err, result, fields) => {
            if (err)
                console.log(err)
            else {
                //console.log(result)
            }
        }
    )

}
const logManagerAction = (req, res, item) => {
    let { user_pk, manager_note, reason_correction } = item;
    let requestIp;
    try {
        requestIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '0.0.0.0'
    } catch (err) {
        requestIp = '0.0.0.0'
    }
    requestIp = ip.address();
    requestIp = requestIp.replaceAll('::ffff:', '');
    db.query("INSERT INTO log_manager_action_table (user_pk, ip, manager_note, reason_correction) VALUES (?, ?, ?, ?)", [user_pk, requestIp, manager_note, reason_correction], (err, result) => {
        if (err) {
            console.log(err);
        } else {
        }
    })
}
const logRequest = (req) => {
    let requestIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip
    requestIp = ip.address();
    let request = {
        url: req.originalUrl,
        headers: req.headers,
        query: req.query,
        params: req.params,
        body: req.body
    }

    request = JSON.stringify(request)
    db.query(
        "INSERT INTO log_information_tb (request, request_ip) VALUES (?, ?)",
        [request, requestIp],
        (err, result, fields) => {
            if (err)
                console.log(err)
            else {
                console.log(result)
            }
        }
    )
}
const queryPromise = (table, sql, type) => {

    return new Promise(async (resolve, reject) => {
        await db.query(sql, (err, result, fields) => {
            if (err) {
                console.log(sql)
                console.log(err)
                reject({
                    code: -200,
                    data: [],
                    table: table
                })
            } else {
                let type_ = type ?? 'list';
                let result_ = undefined;
                if (type_ == 'obj') {
                    result_ = { ...result[0] };
                } else {
                    result_ = [...result];
                }
                resolve({
                    code: 200,
                    data: result_,
                    table: table
                })
            }
        })
    })
}
const getDailyPercentReturn = async () => {
    let result_list = [];
    let sql_list = [
        { table: "daily_percentage", sql: `SELECT * FROM daily_percentage_table` },
    ];
    for (var i = 0; i < sql_list.length; i++) {
        result_list.push(queryPromise(sql_list[i].table, sql_list[i].sql));
    }
    for (var i = 0; i < result_list.length; i++) {
        await result_list[i];
    }
    let result = (await when(result_list));
    let obj = { ...(await result[0])?.data[0] };

    obj['type_percent'] = obj['type_percent'].split(',');
    obj['type_percent'] = {
        point: obj['type_percent'][0],
        star: obj['type_percent'][1],
    }
    obj['money'] = obj['money'].split(',');
    obj['money_percent'] = obj['money_percent'].split(',');
    return obj;
}
const logResponse = (req, res) => {
    let requestIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    requestIp = ip.address();
    let response = JSON.stringify(res)
    // db.query(
    //     "UPDATE log_information_tb SET response=? WHERE request_ip=? ORDER BY pk DESC LIMIT 1",
    //     [response, requestIp],
    //     (err, result, fields) => {
    //         if(err)
    //             console.log(err)
    //         else {
    //             console.log(result)
    //         }
    //     }
    // )
}

/*

*/
const getUserPKArrStrWithNewPK = (userPKArrStr, newPK) => {
    let userPKList = JSON.parse(userPKArrStr)
    if (userPKList.indexOf(newPK) == -1)
        userPKList.push(newPK)
    return JSON.stringify(userPKList)
}

const isNotNullOrUndefined = (paramList) => {
    for (let i in paramList)
        if (i == undefined || i == null)
            return false
    return true
}

// api가 ad인지 product인지 확인 후 파일 네이밍
const namingImagesPath = (api, files) => {
    if (api == "ad") {
        return {
            image: (files) ? "/image/ad/" + files.filename : "/image/ad/defaultAd.png",
            isNull: !(files)
        }
    }
    else if (api == "product") {
        return {
            mainImage: (files.mainImage) ? "/image/item/" + files.mainImage[0].filename : "/image/item/defaultItem.png",
            detailImage: (files.detailImage) ? "/image/detailItem/" + files.detailImage[0].filename : "/image/detailItem/defaultDetail.png",
            qrImage: (files.qrImage) ? "/image/qr/" + files.qrImage[0].filename : "/image/qr/defaultQR.png",
            isNull: [!files.mainImage, !files.detailImage, !files.qrImage]
        }
    }
}
function removeItems(arr, value) {
    var i = 0;
    while (i < arr.length) {
        if (arr[i] === value) {
            arr.splice(i, 1);
        } else {
            ++i;
        }
    }
    return arr;
}

function getSQLnParams(query, params, colNames) {
    let sql = query
    let returnParams = []

    for (let i = 0, count = 0; i < params.length; i++) {
        if (params[i]) {
            if (count > 0)
                sql += ', '
            sql += colNames[i] + '=?'
            returnParams.push(params[i])
            count++
        }
    }
    return { sql, param: returnParams }
}
const updateUserTier = async (pk_) => {
    let pk = pk_;
    let up_point_list = [0, 9000, 30000, 90000, 150000, 300000];//상향 랜덤박스 포인트
    let down_point_list = [0, 3600, 12000, 36000, 60000, 120000];//하향 랜덤박스 포인트
    let user = await dbQueryList(`SELECT *, (SELECT SUM(price) FROM log_randombox_table WHERE user_pk=user_table.pk) AS sum_randombox FROM user_table WHERE pk=${pk}`);
    user = user?.result[0];
    let randombox_point = user?.sum_randombox ?? 0;
    let user_tier = user?.tier ?? 0;
    for (var i = 5; i >= 0; i--) {//상향 for문
        if (randombox_point >= up_point_list[i] && user_tier / 5 < i) {
            await insertQuery(`UPDATE user_table SET tier=? WHERE pk=?`, [i * 5, pk]);
            return;
        }
    }
    for (var i = 0; i <= 5; i++) {//하향 for문
        if (randombox_point < down_point_list[i] && user_tier / 5 >= i) {
            await insertQuery(`UPDATE user_table SET tier=? WHERE pk=?`, [(i - 1) * 5, pk]);
            return;
        }
    }
}
async function response(req, res, code, message, data) {
    var resDict = {
        'result': code,
        'message': message,
        'data': data,
    }
    if (code < 0 || req.originalUrl.includes('login')) {
        //logRequestResponse(req, resDict);
    }
    if (req?.body?.manager_note && code > 0) {
        const decode = checkLevel(req.cookies.token, 40);
        await logManagerAction(req, resDict, {
            user_pk: decode.pk ?? -1,
            manager_note: req?.body?.manager_note ?? "",
            reason_correction: req?.body?.reason_correction ?? ""
        })
    }
    res.send(resDict);
}
function nullResponse(req, res) {
    response(req, res, -200, "입력이 잘못되었습니다.(요청 데이터 확인)", [])
}
function lowLevelResponse(req, res) {
    response(req, res, -200, "권한이 없습니다", [])
}
const returnMoment = (d) => {
    var today = new Date();
    if(d){
        today = d;
    }
    var year = today.getFullYear();
    var month = ('0' + (today.getMonth() + 1)).slice(-2);
    var day = ('0' + today.getDate()).slice(-2);
    var dateString = year + '-' + month + '-' + day;
    var hours = ('0' + today.getHours()).slice(-2);
    var minutes = ('0' + today.getMinutes()).slice(-2);
    var seconds = ('0' + today.getSeconds()).slice(-2);
    var timeString = hours + ':' + minutes + ':' + seconds;
    let moment = dateString + ' ' + timeString;
    return moment;
}
const max_child_depth = () => {//깊이
    return 100;
}
const getEventRandomboxPercentByTier = (num) => {
    return num / 10;
}
const getKewordListBySchema = (schema_) => {
    let schema = schema_;
    let list = [];
    if (schema == 'user') {
        list = ['id', 'name', 'phone'];
    } else if (schema == 'user_subscriptiondeposit') {
        list = ['id', 'name', 'phone'];
    } else if (schema == 'marketing') {
        list = ['u_u.id', 'u_u.name'];
    } else if (schema == 'log_star') {
        list = ['user_table.id', 'user_table.name'];
    } else if (schema == 'log_point') {
        list = ['user_table.id', 'user_table.name'];
    } else if (schema == 'log_randombox') {
        list = ['user_table.id', 'user_table.name'];
    } else if (schema == 'main_banner') {
        list = ['link'];
    } else if (schema == 'notice') {
        list = ['title'];
    } else if (schema == 'log_login') {
        list = ['user_id', 'user_name', 'ip'];
    } else if (schema == 'log_manager_action') {
        list = ['user_table.id', 'user_table.name'];
    } else if (schema == 'exchange') {
        list = ['u_u.id', 'u_u.name', 'u_u.zip_code', 'u_u.bank_name', 'u_u.account_number', 'u_u.account_name'];
    } else {
        link = [];
    }
    return list;
}
const getDiscountPoint = (item_price, is_use_point, point_percent, tier) => {
    console.log(item_price)
    console.log(is_use_point)
    console.log(tier)
    let introduce_percent_list = [0, 6, 7, 8, 9, 10];
    if (is_use_point == 0) {
        return 0;
    } else if (is_use_point == 1) {
        return point_percent;
    } else if (is_use_point == 2) {
        return item_price * introduce_percent_list[tier / 5] / 100;
    } else {
        return 0;
    }
}
const commarNumber = (num) => {
    if (!num && num != 0) {
        return undefined;
    }
    let str = "";
    if (typeof num == "string") {
        str = num;
    } else {
        str = num.toString();
    }
    let decimal = "";
    if (str.includes(".")) {
        decimal = "." + str.split(".")[1].substring(0, 2);
        str = str.split(".")[0];
    } else {
        decimal = "";
    }
    if (str?.length <= 3) {
        return str;
    }
    let result = "";
    let count = 0;
    for (var i = str?.length - 1; i >= 0; i--) {
        if (count % 3 == 0 && count != 0 && !isNaN(parseInt(str[i]))) result = "," + result;
        result = str[i] + result;
        count++;
    }
    return result + decimal;
}
const makeMaxPage = (num, page_cut) => {
    if (num % page_cut == 0) {
        return num / page_cut;
    } else {
        return parseInt(num / page_cut) + 1;
    }
}
const discountOutletList = (tier) => {
    let discount_percent_list = [5, 6, 7, 8, 9, 10];
    return discount_percent_list[tier / 5];
}
const discountOutlet = (price, tier) => {
    let discount_percent_list = [5, 6, 7, 8, 9, 10];
    let result = parseFloat(price);
    console.log(result)
    console.log(tier)
    result = result * (discount_percent_list[tier / 5] / 100);
    return result;
}
function getMonday(d) {
    d = new Date(d);
    var day = d.getDay(),
        diff = d.getDate() - day + (day == 0 ? -6 : 1); // adjust when day is sunday
    return new Date(d.setDate(diff));
}
module.exports = {
    checkLevel, lowLevelException, nullRequestParamsOrBody,
    logRequestResponse, logResponse, logRequest,
    getUserPKArrStrWithNewPK, isNotNullOrUndefined,
    namingImagesPath, getSQLnParams, getKewordListBySchema,
    nullResponse, lowLevelResponse, response, removeItems, returnMoment, formatPhoneNumber,
    categoryToNumber, sendAlarm, updateUserTier, getDailyPercentReturn, queryPromise, max_child_depth,
    getEventRandomboxPercentByTier, getDiscountPoint, commarNumber, makeMaxPage, discountOutletList, discountOutlet, getMonday
}