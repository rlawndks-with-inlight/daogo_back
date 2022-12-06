const express = require('express')
//const { json } = require('body-parser')
const router = express.Router()
const cors = require('cors')
router.use(cors())
router.use(express.json())

const crypto = require('crypto')
//const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const { checkLevel, getSQLnParams, getUserPKArrStrWithNewPK,
    isNotNullOrUndefined, namingImagesPath, nullResponse,
    lowLevelResponse, response, removeItems, returnMoment, formatPhoneNumber, categoryToNumber, sendAlarm
} = require('../util')
const {
    getRowsNumWithKeyword, getRowsNum, getAllDatas,
    getDatasWithKeywordAtPage, getDatasAtPage,
    getKioskList, getItemRows, getItemList, dbQueryList, dbQueryRows, insertQuery, getTableAI
} = require('../query-util')
const macaddress = require('node-macaddress');
const when = require('when');
const db = require('../config/db')
const { upload } = require('../config/multerConfig')
const { Console } = require('console')
const { abort } = require('process')
const axios = require('axios')
//const { pbkdf2 } = require('crypto')
const salt = "435f5ef2ffb83a632c843926b35ae7855bc2520021a73a043db41670bfaeb722"
const saltRounds = 10
const pwBytes = 64
const jwtSecret = "djfudnsqlalfKeyFmfRkwu"
const geolocation = require('geolocation')
const kakaoOpt = {
    clientId: '4a8d167fa07331905094e19aafb2dc47',
    redirectUri: 'http://172.30.1.19:8001/api/kakao/callback',
};

router.get('/', (req, res) => {
    console.log("back-end initialized")
    res.send('back-end initialized')
});


const addAlarm = (req, res) => {
    try {
        // 바로할지, 0-1, 요일, 시간, 
        const { title, note, url, type, start_date, days, time } = req.body;


        db.query("INSERT INTO alarm_table (title, note, url, type, start_date, days, time) VALUES (?, ?, ?, ?, ?, ?, ?)", [title, note, url, type, start_date, days, time], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "알람 추가 실패", [])
            }
            else {
                if (type == 0) {
                    sendAlarm(title, note, "alarm", result.insertId, url);
                    insertQuery("INSERT INTO alarm_log_table (title, note, item_table, item_pk, url) VALUES (?, ?, ?, ?, ?)", [title, note, "alarm", result.insertId, url])
                }
                await db.query("UPDATE alarm_table SET sort=? WHERE pk=?", [result.insertId, result.insertId], (err, result) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "알람 추가 실패", [])
                    }
                    else {
                        return response(req, res, 200, "알람 추가 성공", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        response(req, res, -200, "서버 에러 발생", [])
    }
}
const getNoticeAndAlarmLastPk = (req, res) => {
    try {
        db.query("SELECT * FROM alarm_log_table ORDER BY pk DESC LIMIT 1", async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버에러발생", [])
            }
            else {
                await db.query("SELECT * FROM notice_table ORDER BY pk DESC LIMIT 1", (err, result2) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버에러발생", [])

                    }
                    else {
                        return response(req, res, 100, "success", { alarm_last_pk: result[0]?.pk ?? 0, notice_last_pk: result2[0]?.pk ?? 0 })
                    }
                })
            }
        })
    } catch (e) {

    }
}
const updateAlarm = (req, res) => {
    try {
        // 바로할지, 0-1, 요일, 시간, 
        const { title, note, url, type, start_date, days, time, pk } = req.body;
        db.query("UPDATE alarm_table SET title=?, note=?, url=?, type=?, start_date=?, days=?, time=? WHERE pk=?", [title, note, url, type, start_date, days, time, pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "알람 수정 실패", [])
            }
            else {
                return response(req, res, 200, "알람 수정 성공", [])
            }
        })

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const onSignUp = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0)
        console.log(req.body);
        //logRequest(req)
        const id = req.body.id ?? "";
        const pw = "a123456!";
        const name = req.body.name ?? "";
        const nickname = req.body.nickname ?? "";
        const phone = req.body.phone ?? "";
        const user_level = req.body.user_level ?? 0;
        const parent_id = req.body.parent_id ?? "";
        if (user_level == 0) {//회원추가

        } else {//관리자 추가

        }
        //중복 체크 
        if (decode.user_level < 40 && user_level > 0) {
            return response(req, res, -100, "권한이 없습니다.", [])
        }
        let sql = "SELECT * FROM user_table WHERE id=? "
        let depth = 0;
        db.query(sql, [id, nickname, -10], async (err, result) => {
            if (result.length > 0) {
                return response(req, res, -200, "아이디가 중복됩니다.", [])
            } else {
                await db.query("SELECT * FROM user_table WHERE id=?", [parent_id], async (err, parent_result) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버에러 발생", [])
                    } else {
                        if (parent_result.length > 0 || user_level > 0) {

                            await crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                                // bcrypt.hash(pw, salt, async (err, hash) => {
                                let hash = decoded.toString('base64');

                                if (err) {
                                    console.log(err)
                                    return response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                                }

                                sql = 'INSERT INTO user_table (id, pw, name, nickname , phone, user_level, parent_id, parent_pk, depth) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
                                if (parent_result[0]) {
                                    depth = parent_result[0]?.depth + 1;
                                }
                                await db.query(sql, [id, hash, name, nickname, phone, user_level, parent_result[0]?.id ?? "", parent_result[0]?.pk ?? 0, depth], async (err, result) => {

                                    if (err) {
                                        console.log(err)
                                        return response(req, res, -200, "서버에러 발생", [])
                                    }
                                    else {
                                        return response(req, res, 100, "success", [])
                                    }
                                })
                            })
                        } else {
                            return response(req, res, -100, "추천인 아이디가 존재하지 않습니다.", []);
                        }
                    }
                })

            }
        })

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getAddressByText = async (req, res) => {
    try {
        let { text } = req.body;
        let client_id = 'pmfxkd4ept';
        let client_secret = 't2HIUfZOkme7FF0JdIxfdwYI92cl2R5GKpMBa7Nj';
        let api_url = 'https://naveropenapi.apigw.ntruss.com/map-geocode/v2/geocode'; // json

        const coord = await axios.get(`${api_url}`, {
            params: {
                query: text,
            },
            headers: {
                "X-NCP-APIGW-API-KEY-ID": `${client_id}`,
                "X-NCP-APIGW-API-KEY": `${client_secret}`,
            },
        })
        if (!coord.data.addresses) {
            return response(req, res, 100, "success", []);
        } else {
            let result = [];
            for (var i = 0; i < coord.data.addresses.length; i++) {
                result[i] = {
                    lng: coord.data.addresses[i].x,
                    lat: coord.data.addresses[i].y,
                    road_address: coord.data.addresses[i].roadAddress,
                    address: coord.data.addresses[i].jibunAddress
                }
            }
            return response(req, res, 100, "success", result);
        }
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addCategory = (req, res) => {

}

const onLoginById = async (req, res) => {
    try {
        let { id, pw, type } = req.body;
        let sql = `SELECT * FROM user_table WHERE id=?`;
        if (type == 'manager') {
            sql += ` AND user_level>=30 `
        }
        db.query(sql, [id], async (err, result1) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (result1.length > 0) {
                    await crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                        // bcrypt.hash(pw, salt, async (err, hash) => {
                        let hash = decoded.toString('base64');
                        if (hash == result1[0].pw) {
                            try {
                                const token = jwt.sign({
                                    pk: result1[0].pk,
                                    name: result1[0].name,
                                    id: result1[0].id,
                                    user_level: result1[0].user_level,
                                    phone: result1[0].phone,
                                    profile_img: result1[0].profile_img,
                                    parent_pk: result1[0].parent_pk,
                                    parent_id: result1[0].parent_id,
                                    depth: result1[0].depth,
                                    type: result1[0].type
                                },
                                    jwtSecret,
                                    {
                                        expiresIn: '600m',
                                        issuer: 'fori',
                                    });
                                res.cookie("token", token, { httpOnly: true, maxAge: 60 * 60 * 1000 * 10 });
                                let requestIp;
                                try {
                                    requestIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '0.0.0.0'
                                } catch (err) {
                                    requestIp = '0.0.0.0'
                                }
                                requestIp = requestIp.replaceAll('::ffff:','');
                                let result1_ = await insertQuery('UPDATE user_table SET last_login=? WHERE pk=?', [returnMoment(), result1[0].pk]);
                                let result2_ = await insertQuery('INSERT INTO log_login_table (ip, user_level, user_id, user_name) VALUES (?, ?, ?, ?)', [requestIp, result1[0].user_level, result1[0].id, result1[0].name]);
                                let is_user_lottery_today = await dbQueryList(`SELECT * FROM log_randombox_table WHERE DATE_FORMAT(date,'%Y-%m-%d') = '${returnMoment().substring(0, 10)}' AND user_pk=${result1[0].pk} AND type=7`)
                                if (is_user_lottery_today?.result?.length > 0) {
                                    is_user_lottery_today = true;
                                } else {
                                    is_user_lottery_today = false;
                                }
                                return response(req, res, 200, result1[0].name + ' 님 환영합니다.', { user: result1[0], is_user_lottery_today: is_user_lottery_today });

                            } catch (e) {
                                console.log(e)
                                return response(req, res, -200, "서버 에러 발생", [])
                            }
                        } else {
                            return response(req, res, -100, "아이디 또는 비밀번호를 확인해주세요.", [])

                        }
                    })
                } else {
                    return response(req, res, -100, "아이디 또는 비밀번호를 확인해주세요.", [])
                }
            }
        })

    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const onLoginBySns = (req, res) => {
    try {
        let { id, typeNum, name, nickname, phone, user_level, profile_img } = req.body;
        db.query("SELECT * FROM user_table WHERE id=? AND type=?", [id, typeNum], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (result.length > 0) {//기존유저
                    let token = jwt.sign({
                        pk: result[0].pk,
                        nickname: result[0].nickname,
                        id: result[0].id,
                        user_level: result[0].user_level,
                        phone: result[0].phone,
                        profile_img: result[0].profile_img,
                        depth: result[0].depth,
                        type: typeNum
                    },
                        jwtSecret,
                        {
                            expiresIn: '600m',
                            issuer: 'fori',
                        });
                    res.cookie("token", token, { httpOnly: true, maxAge: 60 * 60 * 1000 * 10 });
                    await db.query('UPDATE user_table SET last_login=? WHERE pk=?', [returnMoment(), result[0].pk], (err, result) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "서버 에러 발생", [])
                        }
                    })
                    return response(req, res, 200, result[0].nickname + ' 님 환영합니다.', result[0]);
                } else {//신규유저
                    return response(req, res, 50, '신규회원 입니다.', []);
                }
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const onLoginByPhone = (req, res) => {
    try {

    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const uploadProfile = (req, res) => {
    try {
        const image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        const id = req.body.id;
        db.query('UPDATE user_table SET profile_img=? WHERE id=?', [image, id], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const editMyInfo = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        let body = { ...req.body };
        delete body['pw'];
        delete body['type'];
        delete body['profile'];

        let pw = await makeHash(req?.body?.pw);
        let db_pw = await dbQueryList(`SELECT * FROM user_table WHERE pk=${decode?.pk}`);
        let keys = Object.keys(body);
        let values = [];
        if (pw?.data === db_pw?.result[0]?.pw) {
            for (var i = 0; i < keys.length; i++) {
                let data = undefined;

                if (keys == 'payment_pw') {
                    data = (await makeHash(body[keys[i]]))?.data;
                } else if (keys == 'new_pw') {
                    data = (await makeHash(body[keys[i]]))?.data;
                    keys[i] = 'pw';
                } else {
                    data = body[keys[i]];
                }
                values.push(data);
            }
            let files = { ...req.files };
            console.log(files)
            let files_keys = Object.keys(files);
            for (var i = 0; i < files_keys.length; i++) {

                values.push(
                    '/image/' + req.files[files_keys][0].fieldname + '/' + req.files[files_keys][0].filename
                );
                keys.push('profile_img');
            }
            let sql = `UPDATE user_table SET ${keys.join("=?,")}=? WHERE pk=?`;
            values.push(decode?.pk);

            db.beginTransaction((err) => {
                if (err) {
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    db.query(sql, values, async (err, result) => {
                        console.log(sql)
                        if (err) {
                            console.log(err)
                            await db.rollback();
                            return response(req, res, -200, "서버 에러 발생", [])
                        }
                        else {
                            await db.commit();
                            return response(req, res, 200, "success", [])
                        }
                    })
                }
            })
        } else {
            return response(req, res, -100, "비밀번호가 일치하지 않습니다.", [])
        }
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const getUserMoney = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0)
        console.log(req.query)
        let pk = 0;
        if (req.query.pk) {
            if (decode?.user_level >= 40) {
                pk = req.query.pk;
            } else {
                return response(req, res, -150, "권한이 없습니다.", []);
            }
        } else {
            if (decode) {
                pk = decode?.pk;
            }
        }
        if (!req?.query?.pk) {
            pk = decode?.pk;
        }
        let result_list = [];

        let sql_list = [
            { table: "randombox", sql: `SELECT SUM(price) AS randombox FROM log_randombox_table WHERE user_pk=${pk}` },
            { table: "star", sql: `SELECT SUM(price) AS star FROM log_star_table WHERE user_pk=${pk}` },
            { table: "point", sql: `SELECT SUM(price) AS point FROM log_point_table WHERE user_pk=${pk}` },
            { table: "esgw", sql: `SELECT SUM(price) AS esgw FROM log_esgw_table WHERE user_pk=${pk}` },
            { table: "user", sql: `SELECT * FROM user_table WHERE pk=${pk}` },
        ];
        if (req?.query?.type == 'subscriptiondeposit') {
            sql_list.push({ table: "star_subscription_deposit", sql: `SELECT SUM(price) AS star_subscription_deposit FROM log_star_table WHERE user_pk=${pk} AND type=8 ` })
            sql_list.push({ table: "point_subscription_deposit", sql: `SELECT SUM(price) AS point_subscription_deposit FROM log_point_table WHERE user_pk=${pk} AND type=8 ` })
            sql_list.push({ table: "esgw_subscription_deposit", sql: `SELECT SUM(price) AS esgw_subscription_deposit FROM log_esgw_table WHERE user_pk=${pk} AND type=8 ` })
        }
        for (var i = 0; i < sql_list.length; i++) {
            result_list.push(queryPromise(sql_list[i].table, sql_list[i].sql));
        }
        for (var i = 0; i < result_list.length; i++) {
            await result_list[i];
        }
        let result = (await when(result_list));
        let obj = {};
        for (var i = 0; i < (await result).length; i++) {
            if ((await result[i])?.table == 'user') {
                obj[(await result[i])?.table] = { ...(await result[i])?.data[0] };
            } else {
                obj[(await result[i])?.table] = (await result[i])?.data[0][(await result[i])?.table] ?? 0;
            }
        }
        return response(req, res, 100, "success", obj)
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getUserMoneyReturn = async (pk) => {
    let result_list = [];
    let sql_list = [
        { table: "randombox", sql: `SELECT SUM(price) AS randombox FROM log_randombox_table WHERE user_pk=${pk}` },
        { table: "star", sql: `SELECT SUM(price) AS star FROM log_star_table WHERE user_pk=${pk}` },
        { table: "point", sql: `SELECT SUM(price) AS point FROM log_point_table WHERE user_pk=${pk}` },
        { table: "esgw", sql: `SELECT SUM(price) AS esgw FROM log_esgw_table WHERE user_pk=${pk}` },
    ];
    for (var i = 0; i < sql_list.length; i++) {
        result_list.push(queryPromise(sql_list[i].table, sql_list[i].sql));
    }
    for (var i = 0; i < result_list.length; i++) {
        await result_list[i];
    }
    let result = (await when(result_list));
    let obj = {};
    for (var i = 0; i < (await result).length; i++) {
        if ((await result[i])?.table == 'user') {
            obj[(await result[i])?.table] = { ...(await result[i])?.data[0] };
        } else {
            obj[(await result[i])?.table] = (await result[i])?.data[0][(await result[i])?.table] ?? 0;
        }
    }
    return obj;
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
const checkUserPointNegative = (obj) => {
    for (var i = 0; i < Object.keys(obj).length; i++) {
        if (obj[Object.keys(obj)[i]] < 0) {
            return true;
        }
    }
    return false;
}
const updateUserMoneyByManager = async (req, res) => {//관리자가 유저 포인트 변동 시
    try {
        const decode = checkLevel(req.cookies.token, 40)
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", []);
        }
        await db.beginTransaction();
        console.log(req.body)
        let { pk, reason_correction, manager_note, edit_list } = req.body;
        let explain_obj = JSON.stringify({
            manager_pk: decode?.pk,
            manager_id: decode.id
        })
        if (edit_list?.length > 0) {
            for (var i = 0; i < edit_list?.length; i++) {
                let result = await insertQuery(`INSERT INTO log_${edit_list[i]?.type}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                    [edit_list[i]?.price, pk, 5, edit_list[i]?.note, explain_obj])
            }
            let user_money = await getUserMoneyReturn(pk);
            let negative_result = await checkUserPointNegative(user_money);
            if (negative_result) {
                await db.rollback();
                return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
            }
            await db.commit();
            return response(req, res, 100, "success", []);
        } else {
            await db.commit();
            return response(req, res, 100, "success", []);
        }
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const lotteryDailyPoint = async (req, res) => {//유저가 데일리포인트 발생 시
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let is_user_lottery_today = await dbQueryList(`SELECT * FROM log_randombox_table WHERE DATE_FORMAT(date,'%Y-%m-%d') = '${returnMoment().substring(0, 10)}' AND user_pk=${decode?.pk} AND type=7`)
        if (is_user_lottery_today?.result?.length > 0) {
            return response(req, res, -100, "오늘 이미 데일리 추첨을 완료하였습니다.", []);
        }
        let user_money = await getUserMoneyReturn(decode?.pk);
        let daily_percent = await getDailyPercentReturn();
        let rand_num = Math.floor(Math.random() * 101);
        let current_num = 0;
        for (var idx = 0; idx < daily_percent?.money_percent?.length; idx++) {
            current_num += daily_percent?.money_percent[idx];
            if (current_num > rand_num) {
                break;
            }
        }
        let randombox_point = (parseFloat(daily_percent?.money[idx]) * user_money?.randombox / 100);
        let log_list = [{ table: 'randombox', price: randombox_point * (-1), user_pk: decode?.pk, type: 7 },
        { table: 'point', price: (randombox_point * parseFloat(daily_percent?.type_percent?.point)) / 100, user_pk: decode?.pk, type: 7 },
        { table: 'star', price: (randombox_point * parseFloat(daily_percent?.type_percent?.star)) / 100, user_pk: decode?.pk, type: 7 }];
        let explain_obj = {
            percent: parseFloat(daily_percent?.money[idx])
        }
        explain_obj = JSON.stringify(explain_obj)

        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, 7, "", explain_obj])
        }
        await db.commit();
        return response(req, res, 100, "success", { percent: daily_percent?.money[idx] });
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const onDailyPoint = (req, res) => {//관리자가 데일리포인트 발생시

}
const onGift = async (req, res) => {//선물
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let { receiver_id, receiver_phone, send_star, send_point, payment_pw } = req.body;
        let receiver_user = await dbQueryList(`SELECT * FROM user_table WHERE id='${receiver_id}'`);
        receiver_user = receiver_user?.result[0] ?? {};
        let user = await dbQueryList(`SELECT * FROM user_table WHERE pk=${decode?.pk}`);
        user = user?.result[0];
        let insert_payment_pw = await makeHash(payment_pw);
        if (insert_payment_pw?.data !== user?.payment_pw) {
            return response(req, res, -100, "결제 비밀번호가 틀렸습니다.", []);
        }
        if (receiver_user?.pk == decode?.pk) {
            return response(req, res, -100, "자기 자신에게 선물을 줄 수 없습니다.", []);
        }
        if (receiver_phone !== receiver_user?.phone.substring(receiver_user?.phone.length - 4, receiver_user?.phone.length)) {
            return response(req, res, -100, "받는사람 휴대폰 마지막 4자리가 틀렸습니다.", []);
        }
        if ((send_star < 0 && send_star) || (send_point < 0 && send_point)) {
            return response(req, res, -100, "0 이상의 숫자를 입력해주세요.", []);
        }
        let log_list = [];
        if (send_star && send_star > 0) {
            log_list.push({ table: 'star', price: send_star * (-1), user_pk: decode?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: receiver_user?.pk, user_id: receiver_user?.id, user_name: receiver_user?.name }) })
            log_list.push({ table: 'star', price: send_star*(97/100), user_pk: receiver_user?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: decode?.pk, user_id: decode?.id, user_name: decode?.name }) })
        }
        if (send_point && send_point > 0) {
            log_list.push({ table: 'point', price: send_point * (-1), user_pk: decode?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: receiver_user?.pk, user_id: receiver_user?.id, user_name: receiver_user?.name }) })
            log_list.push({ table: 'point', price: send_point*(97/100), user_pk: receiver_user?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: decode?.pk, user_id: decode?.id, user_name: decode?.name }) })
        }
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", log_list[i]?.explain_obj])
        }
        let user_money = await getUserMoneyReturn(decode?.pk);
        let negative_result = await checkUserPointNegative(user_money);
        if (negative_result) {
            await db.rollback();
            return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
        }
        await db.commit();
        return response(req, res, 100, "success", []);
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const registerRandomBox = async (req, res) => {//랜덤박스 등록
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let { star, payment_pw } = req.body;
        if (star < 1) {
            return response(req, res, -100, "스타는 1 이상의 금액부터 등록 가능합니다.", []);
        }
        if (star % 100 != 0) {
            return response(req, res, -100, "스타는 100 단위 금액만 등록 가능합니다.", []);
        }
        let user = await dbQueryList(`SELECT * FROM user_table WHERE pk=${decode?.pk}`);
        user = user?.result[0];
        let insert_payment_pw = await makeHash(payment_pw);
        if (insert_payment_pw?.data !== user?.payment_pw) {
            return response(req, res, -100, "결제 비밀번호가 틀렸습니다.", []);
        }
        let log_list = [
            { table: 'star', price: star * (-1), user_pk: decode?.pk, type: 2 },
            { table: 'randombox', price: star * 3, user_pk: decode?.pk, type: 2 }
        ]
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, 2, "", ""])
        }
        let user_money = await getUserMoneyReturn(decode?.pk);
        let negative_result = await checkUserPointNegative(user_money);
        if (negative_result) {
            await db.rollback();
            return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
        }
        await db.commit();
        return response(req, res, 100, "success", []);
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const requestWithdraw = async (req, res) => {//출금신청
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let { star, payment_pw } = req.body;
        if (star < 500) {
            return response(req, res, -100, "스타는 500 이상의 금액부터 등록 가능합니다.", []);
        }
        if (star % 100 != 0) {
            return response(req, res, -100, "스타는 100 단위 금액만 등록 가능합니다.", []);
        }
        let user = await dbQueryList(`SELECT * FROM user_table WHERE pk=${decode?.pk}`);
        user = user?.result[0];
        let insert_payment_pw = await makeHash(payment_pw);
        if (insert_payment_pw?.data !== user?.payment_pw) {
            return response(req, res, -100, "결제 비밀번호가 틀렸습니다.", []);
        }
        let log_list = [
            { table: 'star', price: star * (-1), user_pk: decode?.pk, type: 4 },
        ]
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", JSON.stringify({ status: 0 })])//0-출금전, 1-출금완료
        }
        let user_money = await getUserMoneyReturn(decode?.pk);
        let negative_result = await checkUserPointNegative(user_money);
        if (negative_result) {
            await db.rollback();
            return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
        }
        await db.commit();
        return response(req, res, 100, "success", []);
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const buyESGWPoint = async (req, res) => {//esgw 포인트 등록
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let { point, payment_pw } = req.body;
        if (point < 10) {
            return response(req, res, -100, "포인트는 10 이상의 금액부터 등록 가능합니다.", []);
        }
        let user = await dbQueryList(`SELECT * FROM user_table WHERE pk=${decode?.pk}`);
        user = user?.result[0];
        let insert_payment_pw = await makeHash(payment_pw);
        if (insert_payment_pw?.data !== user?.payment_pw) {
            return response(req, res, -100, "결제 비밀번호가 틀렸습니다.", []);
        }
        let log_list = [
            { table: 'point', price: point * (-1), user_pk: decode?.pk, type: 9 },
            { table: 'esgw', price: point / 10, user_pk: decode?.pk, type: 9 },
        ]
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", "{}"])//0-출금전, 1-출금완료
        }
        let user_money = await getUserMoneyReturn(decode?.pk);
        let negative_result = await checkUserPointNegative(user_money);
        if (negative_result) {
            await db.rollback();
            return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
        }
        await db.commit();
        return response(req, res, 100, "success", []);
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const subscriptionDeposit = async (req, res) => {//청약예치금 등록
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let { star, point, esgw, payment_pw } = req.body;
        console.log(req.body)
        let user = await dbQueryList(`SELECT * FROM user_table WHERE pk=${decode?.pk}`);
        user = user?.result[0];
        let insert_payment_pw = await makeHash(payment_pw);
        if (insert_payment_pw?.data !== user?.payment_pw) {
            return response(req, res, -100, "결제 비밀번호가 틀렸습니다.", []);
        }
        if (star < 1 && star) {
            return response(req, res, -100, "스타는 1 이상의 금액부터 등록 가능합니다.", []);
        }
        if (point < 1 && point) {
            return response(req, res, -100, "포인트는 1 이상의 금액부터 등록 가능합니다.", []);
        }
        if (esgw < 1 && esgw) {
            return response(req, res, -100, "ESGW포인트는 1 이상의 금액부터 등록 가능합니다.", []);
        }
        let log_list = [];
        if (star) {
            log_list.push({ table: 'star', price: star * (-1), user_pk: decode?.pk, type: 8 })
        }
        if (point) {
            log_list.push({ table: 'point', price: point * (-1), user_pk: decode?.pk, type: 8 })
        }
        if (esgw) {
            log_list.push({ table: 'esgw', price: esgw * (-1), user_pk: decode?.pk, type: 8 })
        }
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", "{}"])//0-출금전, 1-출금완료
        }
        let user_money = await getUserMoneyReturn(decode?.pk);
        let negative_result = await checkUserPointNegative(user_money);
        if (negative_result) {
            await db.rollback();
            return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
        }
        await db.commit();
        return response(req, res, 100, "success", []);
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const onOutletOrder = async (req, res) =>{
    try{

    }catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const updateUserMoney = (req, res) => {
    try {

    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const onResign = (req, res) => {
    try {
        let { id } = req.body;
        db.query("DELETE FROM user_table WHERE id=?", [id], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -100, "서버 에러 발생", []);
            } else {
                return response(req, res, 100, "success", []);
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const kakaoCallBack = (req, res) => {
    try {
        const token = req.body.token;
        async function kakaoLogin() {
            let tmp;

            try {
                const url = 'https://kapi.kakao.com/v2/user/me';
                const Header = {
                    headers: {
                        Authorization: `Bearer ${token}`,
                    },
                };
                tmp = await axios.get(url, Header);
            } catch (e) {
                console.log(e);
                return response(req, res, -200, "서버 에러 발생", [])
            }

            try {
                const { data } = tmp;
                const { id, properties } = data;
                return response(req, res, 100, "success", { id, properties });

            } catch (e) {
                console.log(e);
                return response(req, res, -100, "서버 에러 발생", [])
            }

        }
        kakaoLogin();

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}



const sendAligoSms = ({ receivers, message }) => {
    return axios.post('https://apis.aligo.in/send/', null, {
        params: {
            key: 'xbyndmadqxp8cln66alygdq12mbpj7p7',
            user_id: 'firstpartner',
            sender: '1522-1233',
            receiver: receivers.join(','),
            msg: message
        },
    }).then((res) => res.data).catch(err => {
        console.log('err', err);
    });
}
const sendSms = (req, res) => {
    try {
        let receiver = req.body.receiver;
        const content = req.body.content;
        sendAligoSms({ receivers: receiver, message: content }).then((result) => {
            if (result.result_code == '1') {
                return response(req, res, 100, "success", [])
            } else {
                return response(req, res, -100, "fail", [])
            }
        });
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const findIdByPhone = (req, res) => {
    try {
        const phone = req.body.phone;
        db.query("SELECT pk, id FROM user_table WHERE phone=?", [phone], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", result[0])
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const findAuthByIdAndPhone = (req, res) => {
    try {
        const id = req.body.id;
        const phone = req.body.phone;
        db.query("SELECT * FROM user_table WHERE id=? AND phone=?", [id, phone], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (result.length > 0) {
                    return response(req, res, 100, "success", result[0]);
                } else {
                    return response(req, res, -50, "아이디 또는 비밀번호를 확인해주세요.", []);
                }
            }
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const checkExistId = (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 40)
        const id = req.body.id;
        const is_get_user_info = req.body.is_get_user_info;
        if (!decode && is_get_user_info) {
            return response(req, res, -150, "권한이 없습니다.", []);
        }
        db.query(`SELECT * FROM user_table WHERE id=? `, [id], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (is_get_user_info) {
                    if (result.length > 0) {
                        return response(req, res, 100, "success", result[0]);
                    } else {
                        return response(req, res, -100, "존재하지 않은 판매자 아이디입니다.", []);
                    }
                } else {
                    if (result.length > 0) {
                        return response(req, res, -50, "이미 사용중인 아이디입니다.", []);
                    } else {
                        return response(req, res, 100, "사용가능한 아이디입니다.", []);
                    }
                }

            }
        })

    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const checkExistNickname = (req, res) => {
    try {
        const nickname = req.body.nickname;
        db.query(`SELECT * FROM user_table WHERE nickname=? `, [nickname], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (result.length > 0) {
                    return response(req, res, -50, "이미 사용중인 닉네임입니다.", []);
                } else {
                    return response(req, res, 100, "사용가능한 닉네임입니다.", []);
                }
            }
        })

    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const changePassword = (req, res) => {
    try {
        const id = req.body.id;
        let pw = req.body.pw;
        crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
            // bcrypt.hash(pw, salt, async (err, hash) => {
            let hash = decoded.toString('base64')

            if (err) {
                console.log(err)
                return response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
            }

            await db.query("UPDATE user_table SET pw=? WHERE id=?", [hash, id], (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    return response(req, res, 100, "success", [])
                }
            })
        })
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getUserToken = async (req, res) => {
    try {

        const decode = checkLevel(req.cookies.token, 0)
        if (decode) {
            let obj = decode;
            let result = await dbQueryList(`SELECT * FROM user_table WHERE pk=${decode?.pk}`);
            console.log(result)
            if (result?.code > 0) {
                res.send(result?.result[0]);
            } else {
                res.send({
                    pk: -1,
                    level: -1
                })
            }
        } else {
            res.send({
                pk: -1,
                level: -1
            })
        }
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const onLogout = (req, res) => {
    try {
        res.clearCookie('token')
        //res.clearCookie('rtoken')
        return response(req, res, 200, "로그아웃 성공", [])
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getUsers = (req, res) => {
    try {
        let sql = "SELECT * FROM user_table ";
        let pageSql = "SELECT COUNT(*) FROM user_table ";
        let page_cut = req.query.page_cut;
        let status = req.query.status;
        let keyword = req.query.keyword;
        let whereStr = " WHERE 1=1 ";
        if (req.query.level) {
            if (req.query.level == 0) {
                whereStr += ` AND user_level <= ${req.query.level} `;
            } else {
                whereStr += ` AND user_level=${req.query.level} `;
            }
        }
        if (status) {
            whereStr += ` AND status=${status} `;
        }
        if (keyword) {
            whereStr += ` AND (id LIKE '%${keyword}%' OR name LIKE '%${keyword}%' OR nickname LIKE '%${keyword}%')`;
        }
        if (!page_cut) {
            page_cut = 15
        }
        pageSql = pageSql + whereStr;
        sql = sql + whereStr + " ORDER BY sort DESC ";
        if (req.query.page) {
            sql += ` LIMIT ${(req.query.page - 1) * page_cut}, ${page_cut}`;
            db.query(pageSql, async (err, result1) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    await db.query(sql, (err, result2) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "서버 에러 발생", [])
                        } else {
                            let maxPage = result1[0]['COUNT(*)'] % page_cut == 0 ? (result1[0]['COUNT(*)'] / page_cut) : ((result1[0]['COUNT(*)'] - result1[0]['COUNT(*)'] % page_cut) / page_cut + 1);
                            return response(req, res, 100, "success", { data: result2, maxPage: maxPage });
                        }
                    })
                }
            })
        } else {
            db.query(sql, (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    return response(req, res, 100, "success", result)
                }
            })
        }
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const updateUser = async (req, res) => {
    try {
        let { id, pw, name, nickname, phone, user_level, payment_pw, zip_code, address, address_detail, bank_name, account_number, account_name } = req.body;

        const pk = req.body.pk ?? 0;
        if (pw) {
            await crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                // bcrypt.hash(pw, salt, async (err, hash) => {
                let hash = decoded.toString('base64')
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                } else {
                    await db.query("UPDATE user_table SET pw=? WHERE pk=?", [hash, pk], (err, result) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "비밀번호 insert중 에러발생", [])
                        } else {
                        }
                    })
                }
            })
        }
        await db.query("UPDATE user_table SET id=?, name=?, nickname=?, phone=?, user_level=? WHERE pk=?", [id, name, nickname, phone, user_level, pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버에러발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getUserStatistics = (req, res) => {
    try {

    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addMaster = (req, res) => {
    try {
        const id = req.body.id ?? "";
        const pw = req.body.pw ?? "";
        const name = req.body.name ?? "";
        const nickname = req.body.nickname ?? "";
        const user_level = req.body.user_level ?? 30;
        const masterImg = '/image/' + req.files.master[0].fieldname + '/' + req.files.master[0].filename;
        const channelImg = '/image/' + req.files.channel[0].fieldname + '/' + req.files.channel[0].filename;
        //중복 체크 
        let sql = "SELECT * FROM user_table WHERE id=?"

        db.query(sql, [id], (err, result) => {
            if (result.length > 0)
                return response(req, res, -200, "ID가 중복됩니다.", [])
            else {
                crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                    // bcrypt.hash(pw, salt, async (err, hash) => {
                    let hash = decoded.toString('base64')

                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                    }

                    sql = 'INSERT INTO user_table (id, pw, name, nickname, user_level, profile_img, channel_img) VALUES (?, ?, ?, ?, ?, ?, ?)'
                    await db.query(sql, [id, hash, name, nickname, user_level, masterImg, channelImg], async (err, result) => {

                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "회원 추가 실패", [])
                        }
                        else {
                            await db.query("UPDATE user_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                                if (err) {
                                    console.log(err)
                                    return response(req, res, -200, "회원 추가 실패", [])
                                }
                                else {
                                    return response(req, res, 200, "회원 추가 성공", [])
                                }
                            })
                        }
                    })
                })
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateMaster = (req, res) => {
    try {
        const id = req.body.id ?? "";
        let pw = req.body.pw ?? "";
        const name = req.body.name ?? "";
        const nickname = req.body.nickname ?? "";
        const pk = req.body.pk;
        let masterImg = "";
        let channelImg = "";
        let sql = "SELECT * FROM user_table WHERE id=? AND pk!=?"
        db.query(sql, [id, pk], async (err, result) => {
            if (result?.length > 0)
                return response(req, res, -200, "ID가 중복됩니다.", [])
            else {
                let columns = " id=?, name=?, nickname=? ";
                let zColumn = [id, name, nickname];
                await crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                    // bcrypt.hash(pw, salt, async (err, hash) => {
                    let hash = decoded.toString('base64')
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                    } else {
                        if (pw) {
                            columns += ", pw =?"
                            zColumn.push(hash);
                        }
                        if (req.files.master) {
                            masterImg = '/image/' + req.files.master[0].fieldname + '/' + req.files.master[0].filename;
                            columns += ", profile_img=?"
                            zColumn.push(masterImg);
                        }
                        if (req.files.channel) {
                            channelImg = '/image/' + req.files.channel[0].fieldname + '/' + req.files.channel[0].filename;
                            columns += ", channel_img=?"
                            zColumn.push(channelImg);
                        }
                        zColumn.push(pk)
                        await db.query(`UPDATE user_table SET ${columns} WHERE pk=?`, zColumn, (err, result) => {
                            if (err) {
                                console.log(err)
                                return response(req, res, -200, "서버 에러 발생", [])
                            } else {
                                return response(req, res, 100, "success", [])
                            }
                        })
                    }
                })

            }
        })

    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addChannel = (req, res) => {
    try {
        const id = req.body.id ?? "";
        const pw = req.body.pw ?? "";
        const name = req.body.name ?? "";
        const nickname = req.body.nickname ?? "";
        const user_level = req.body.user_level ?? 25;
        let image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        let sql = "SELECT * FROM user_table WHERE id=?"

        db.query(sql, [id], (err, result) => {
            if (result.length > 0)
                return response(req, res, -200, "ID가 중복됩니다.", [])
            else {
                crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
                    // bcrypt.hash(pw, salt, async (err, hash) => {
                    let hash = decoded.toString('base64')

                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "비밀번호 암호화 도중 에러 발생", [])
                    }

                    sql = 'INSERT INTO user_table (id, pw, name, nickname, user_level, channel_img) VALUES (?, ?, ?, ?, ?, ?)'
                    await db.query(sql, [id, hash, name, nickname, user_level, image], async (err, result) => {

                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "fail", [])
                        }
                        else {
                            await db.query("UPDATE user_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                                if (err) {
                                    console.log(err)
                                    return response(req, res, -200, "fail", [])
                                }
                                else {
                                    return response(req, res, 200, "success", [])
                                }
                            })
                        }
                    })
                })
            }
        })

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateChannel = (req, res) => {
    try {
        let nickname = req.body.nickname;
        const pk = req.body.pk;
        let image = "";
        let columns = " nickname=? ";
        let zColumn = [nickname];
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
            columns += ", channel_img=? ";
            zColumn.push(image);
        }
        zColumn.push(pk);
        db.query(`UPDATE user_table SET ${columns} WHERE pk=?`, zColumn, (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "fail", [])
            }
            else {
                return response(req, res, 200, "성공적으로 수정되었습니다.", [])
            }
        })

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
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
const makeHash = (pw_) => {

    return new Promise(async (resolve, reject) => {
        let pw = pw_;
        if (!(typeof pw_ == 'string')) {
            pw.toString();
        }
        await crypto.pbkdf2(pw, salt, saltRounds, pwBytes, 'sha512', async (err, decoded) => {
            // bcrypt.hash(pw, salt, async (err, hash) => {
            let hash = decoded.toString('base64');
            if (err) {
                reject({
                    code: -200,
                    data: undefined,
                })
            } else {
                resolve({
                    code: 200,
                    data: hash,
                })
            }
        })
    })
}
const getGenealogy = (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        let pk = decode.pk;
        db.query("SELECT * FROM user_table", (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                let list = [...result];
                let pk_idx_obj = {};
                for (var i = 0; i < list.length; i++) {
                    pk_idx_obj[list[i].pk] = i;
                }
                let depth_list = [];
                for (var i = 0; i < 100; i++) {
                    depth_list[i] = {};
                }
                if (decode.user_level < 40) {//유저가 불러올 때
                    depth_list[decode?.depth + 1][`${decode?.pk}`] = [];
                    list = list.sort(function (a, b) {
                        return a.depth - b.depth;
                    })
                    for (var i = 0; i < list.length; i++) {
                        if (depth_list[list[i]?.depth][list[i]?.parent_pk] && list[i]?.depth) {
                            depth_list[list[i]?.depth][list[i]?.parent_pk].push(list[i]);
                            depth_list[list[i]?.depth + 1][`${list[i]?.pk}`] = [];
                        }
                    }
                    depth_list[decode?.depth][`${decode?.parent_pk}`] = [{ ...decode }];
                } else {//관리자가 불러올 때
                    for (var i = 0; i < list.length; i++) {
                        if (!depth_list[list[i]?.depth][`${list[i]?.parent_pk}`]) {
                            depth_list[list[i]?.depth][`${list[i]?.parent_pk}`] = [];
                        }
                        depth_list[list[i]?.depth][`${list[i]?.parent_pk}`].push(list[i]);
                        depth_list[list[i]?.depth + 1][`${list[i]?.pk}`] = [];
                    }
                }
                return response(req, res, 100, "success", { data: depth_list, mine: decode });
            }
        })
    } catch (err) {

    }
}
const getHomeContent = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", []);
        }
        console.log(decode)
        let result_list = [];

        let sql_list = [
            // {table:"randombox",sql:""},
            //  {table:"star",sql:""},
            // {table:"point",sql:""},
            { table: "user", sql: "SELECT id, parent_pk, parent_id, name, nickname, profile_img FROM user_table", type: 'obj' },
            { table: "notice", sql: "SELECT * FROM notice_table WHERE status=1 ORDER BY sort DESC LIMIT 0, 3", type: 'list' },
            { table: "randombox", sql: `SELECT SUM(price) AS randombox FROM log_randombox_table WHERE user_pk=${decode.pk}`, type: 'obj' },
            { table: "star", sql: `SELECT SUM(price) AS star FROM log_star_table WHERE user_pk=${decode.pk}`, type: 'obj' },
            { table: "esgw", sql: `SELECT SUM(price) AS esgw FROM log_esgw_table WHERE user_pk=${decode.pk}`, type: 'obj' },
            { table: "point", sql: `SELECT SUM(price) AS point FROM log_point_table WHERE user_pk=${decode.pk}`, type: 'obj' },
            { table: "star_gift", sql: `SELECT SUM(price) AS star_gift FROM log_star_table WHERE user_pk=${decode.pk} AND type=3 AND price > 0 `, type: 'obj' },//선물받은것
            { table: "point_gift", sql: `SELECT SUM(price) AS point_gift FROM log_point_table WHERE user_pk=${decode.pk} AND type=3 AND price > 0 `, type: 'obj' },//선물받은것
        ];

        for (var i = 0; i < sql_list.length; i++) {
            result_list.push(queryPromise(sql_list[i].table, sql_list[i].sql, sql_list[i].type));
        }
        for (var i = 0; i < result_list.length; i++) {
            await result_list[i];
        }
        let result = (await when(result_list));
        let obj = {};
        for (var i = 0; i < (await result).length; i++) {
            obj[(await result[i])?.table] = (await result[i])?.data;
        }
        obj['auth'] = { ...decode };
        return response(req, res, 100, "success", obj)

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getChannelList = (req, res) => {
    try {
        db.query("SELECT * FROM user_table WHERE user_level IN (25, 30) ", (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", result)
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getVideo = (req, res) => {
    try {
        const pk = req.params.pk;
        let sql = `SELECT video_table.* , user_table.nickname, user_table.name FROM video_table LEFT JOIN user_table ON video_table.user_pk = user_table.pk WHERE video_table.pk=${pk} LIMIT 1`;
        db.query(sql, async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                let relate_video = JSON.parse(result[0].relate_video);
                relate_video = relate_video.join();
                await db.query(`SELECT title,date,pk FROM video_table WHERE pk IN (${relate_video})`, (err, result2) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버 에러 발생", [])
                    } else {
                        return response(req, res, 100, "success", { video: result[0], relate: result2 })
                    }
                })
            }
        })
        db.query(sql)
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getVideoContent = (req, res) => {
    try {
        const pk = req.query.pk;
        let sql1 = `SELECT video_table.* , user_table.nickname, user_table.name FROM video_table LEFT JOIN user_table ON video_table.user_pk = user_table.pk WHERE video_table.pk=? LIMIT 1`;//비디오 정보
        let sql2 = `SELECT video_relate_table.*, video_table.* FROM video_relate_table LEFT JOIN video_table ON video_relate_table.relate_video_pk = video_table.pk WHERE video_relate_table.video_pk=? `//관련영상
        let sql3 = `SELECT video_table.pk, video_table.link, video_table.title, user_table.name, user_table.nickname FROM video_table LEFT JOIN user_table ON video_table.user_pk = user_table.pk ORDER BY pk DESC LIMIT 5`;//최신영상
        if (req.query.views) {
            db.query("UPDATE video_table SET views=views+1 WHERE pk=?", [pk], (err, result_view) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                }
            })
        }
        db.query(sql1, [pk], async (err, result1) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                await db.query(sql2, [pk], async (err, result2) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버 에러 발생", [])
                    } else {
                        await db.query(sql3, async (err, result3) => {
                            if (err) {
                                console.log(err)
                                return response(req, res, -200, "서버 에러 발생", [])
                            } else {
                                return response(req, res, 100, "success", {
                                    video: result1[0],
                                    relates: result2,
                                    latests: result3
                                })
                            }
                        })
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getComments = (req, res) => {
    try {
        const { pk, category } = req.query;
        let zColumn = [];
        let columns = ""
        if (pk) {
            zColumn.push(pk)
            columns += " AND comment_table.item_pk=? ";
        }
        if (category) {
            zColumn.push(category)
            columns += " AND comment_table.category_pk=? ";
        }
        db.query(`SELECT comment_table.*, user_table.nickname, user_table.profile_img FROM comment_table LEFT JOIN user_table ON comment_table.user_pk = user_table.pk WHERE 1=1 ${columns} ORDER BY pk DESC`, zColumn, (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "fail", [])
            }
            else {
                return response(req, res, 200, "success", result)
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addComment = (req, res) => {
    try {
        const { userPk, userNick, pk, parentPk, title, note, category } = req.body;
        db.query("INSERT INTO comment_table (user_pk, user_nickname, item_pk, item_title, note, category_pk, parent_pk) VALUES (?, ?, ?, ?, ?, ?, ?)", [userPk, userNick, pk, title, note, category, parentPk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "fail", [])
            }
            else {
                return response(req, res, 200, "success", [])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateComment = (req, res) => {
    try {

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getCommentsManager = (req, res) => {
    try {
        let sql = `SELECT COUNT(*) FROM comment_table `
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addOneWord = (req, res) => {
    try {
        const { title, hash, suggest_title, note, user_pk } = req.body;
        let zColumn = [title, hash, suggest_title, note, user_pk];
        let columns = "(title, hash, suggest_title, note, user_pk";
        let values = "(?, ?, ?, ?, ?";
        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        } else {
            image = req.body.url ?? "";
        }
        zColumn.push(image);
        columns += ', main_img)'
        values += ',?)'
        db.query(`INSERT INTO oneword_table ${columns} VALUES ${values}`, zColumn, async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                await db.query("UPDATE oneword_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "fail", []);
                    }
                    else {
                        return response(req, res, 200, "success", []);
                    }
                })

            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", []);
    }
}
const addOneEvent = (req, res) => {
    try {
        const { title, hash, suggest_title, note, user_pk } = req.body;
        let zColumn = [title, hash, suggest_title, note, user_pk];
        let columns = "(title, hash, suggest_title, note, user_pk";
        let values = "(?, ?, ?, ?, ?";
        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        } else {
            image = req.body.url ?? "";
        }
        zColumn.push(image);
        columns += ', main_img)'
        values += ',?)'
        db.query(`INSERT INTO oneevent_table ${columns} VALUES ${values}`, zColumn, async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                await db.query("UPDATE oneevent_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "fail", [])
                    }
                    else {
                        return response(req, res, 200, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getKoreaByEng = (str) => {
    let ans = "";
    if (str == 'oneword') {
        ans = "하루1단어: ";
    } else if (str == 'oneevent') {
        ans = "하루1종목: ";
    } else if (str == 'theme') {
        ans = "핵심테마: ";
    } else if (str == 'strategy') {
        ans = "전문가칼럼: ";
    } else if (str == 'issue') {
        ans = "핵심이슈: ";
    } else if (str == 'feature') {
        ans = "특징주: ";
    }
    return ans;
}
const addItem = (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        let body = { ...req.body };
        delete body['table'];
        delete body['reason_correction'];
        delete body['manager_note'];
        let keys = Object.keys(body);
        let values = [];
        let values_str = "";

        for (var i = 0; i < keys.length; i++) {
            values.push(body[keys[i]]);
            if (i != 0) {
                values_str += ",";
            }
            values_str += " ?";
        }
        let files = { ...req.files };
        let files_keys = Object.keys(files);
        for (var i = 0; i < files_keys.length; i++) {
            values.push(
                '/image/' + req.files[files_keys][0].fieldname + '/' + req.files[files_keys][0].filename
            );
            keys.push('img_src');
            values_str += ", ?"
        }
        let table = req.body.table;
        let sql = `INSERT INTO ${table}_table (${keys.join()}) VALUES (${values_str}) `;
        db.query(sql, values, async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            }
            else {
                await db.query(`UPDATE ${table}_table SET sort=? WHERE pk=?`, [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "fail", [])
                    } else {
                        return response(req, res, 200, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const updateItem = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        let body = { ...req.body };
        console.log(body)

        delete body['table'];
        delete body['pk'];
        delete body['hash_list'];
        delete body['reason_correction'];
        delete body['manager_note'];
        let keys = Object.keys(body);
        let values = [];
        let values_str = "";
        if (req.body.hash_list && req.body.hash_list?.length > 0) {
            for (var i = 0; i < req.body.hash_list?.length; i++) {
                let hash_result = await makeHash(body[req.body.hash_list[i]]);
                if (!hash_result) {
                    return response(req, res, -100, "fail", [])
                } else {
                    body[req.body.hash_list[i]] = hash_result?.data;
                }
            }
        }

        for (var i = 0; i < keys.length; i++) {
            values.push(body[keys[i]]);
            if (i != 0) {
                values_str += ",";
            }
            values_str += " ?";
        }
        let files = { ...req.files };
        console.log(files)
        let files_keys = Object.keys(files);
        for (var i = 0; i < files_keys.length; i++) {
            values.push(
                '/image/' + req.files[files_keys][0].fieldname + '/' + req.files[files_keys][0].filename
            );
            keys.push('img_src');
            values_str += ", ?"
        }
        let table = req.body.table;
        let sql = `UPDATE ${table}_table SET ${keys.join("=?,")}=? WHERE pk=?`;
        values.push(req.body.pk);
        db.beginTransaction((err) => {
            if (err) {
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                db.query(sql, values, async (err, result) => {
                    if (err) {
                        console.log(err)
                        response(req, res, -200, "서버 에러 발생", [])
                        return db.rollback();
                    }
                    else {
                        return response(req, res, 200, "success", [])
                    }
                })
            }
        })

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const getAllDataByTables = async (req, res) => {
    try {
        let result_list = [];
        let tables = req.body.tables;
        for (var i = 0; i < tables.length; i++) {
            result_list.push(queryPromise(tables[i], `SELECT * FROM ${tables[i]}_table ORDER BY pk DESC`));
        }
        for (var i = 0; i < result_list.length; i++) {
            await result_list[i];
        }
        let ans = (await when(result_list));
        let result = {};
        for (var i = 0; i < ans.length; i++) {
            result[(await ans[i])?.table] = (await ans[i])?.data
        }
        return response(req, res, 100, "success", result);

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const deleteItem = (req, res) => {
    try {
        let pk = req.body.pk ?? 0;
        let table = req.body.table ?? "";
        let sql = `DELETE FROM ${table}_table WHERE pk=? `
        db.query(sql, [pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addIssueCategory = (req, res) => {
    try {
        const { title, sub_title } = req.body;
        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        }
        db.query("INSERT INTO issue_category_table (title,sub_title,main_img) VALUES (?,?,?)", [title, sub_title, image], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                await db.query("UPDATE issue_category_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "fail", [])
                    }
                    else {
                        return response(req, res, 200, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateIssueCategory = (req, res) => {
    try {
        const { title, sub_title, pk } = req.body;
        let zColumn = [title, sub_title];
        let columns = " title=?, sub_title=? ";

        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
            zColumn.push(image);
            columns += ', main_img=? '
        }
        zColumn.push(pk)
        db.query(`UPDATE issue_category_table SET ${columns} WHERE pk=?`, zColumn, (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                return response(req, res, 100, "success", []);
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const addFeatureCategory = (req, res) => {
    try {
        const { title, sub_title } = req.body;
        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        }
        db.query("INSERT INTO feature_category_table (title,sub_title,main_img) VALUES (?,?,?)", [title, sub_title, image], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                await db.query("UPDATE feature_category_table SET sort=? WHERE pk=?", [result?.insertId, result?.insertId], (err, resultup) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "fail", [])
                    }
                    else {
                        return response(req, res, 200, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateFeatureCategory = (req, res) => {
    try {
        const { title, sub_title, pk } = req.body;
        let zColumn = [title, sub_title];
        let columns = " title=?, sub_title=? ";

        let image = "";
        if (req.file) {
            image = '/image/' + req.file.fieldname + '/' + req.file.filename;
            zColumn.push(image);
            columns += ', main_img=? '
        }
        zColumn.push(pk)
        db.query(`UPDATE feature_category_table SET ${columns} WHERE pk=?`, zColumn, (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", []);
            } else {
                return response(req, res, 100, "success", []);
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const getItem = async (req, res) => {
    try {
        let table = req.query.table ?? "user";
        let pk = req.query.pk ?? 0;
        let whereStr = " WHERE pk=? ";
        if (table == "setting") {
            whereStr = "";
        }

        let sql = `SELECT * FROM ${table}_table ` + whereStr;
        if (req.query?.views) {
            let result = await insertQuery(`UPDATE ${table}_table SET views=views+1 WHERE pk=${pk}`, []);
        }
        if(table=='outlet'){
            sql = "SELECT outlet_table.*, outlet_category_table.name AS category_name,outlet_brand_table.name AS brand_name from ";
            sql += " outlet_table LEFT JOIN outlet_category_table ON outlet_table.category_pk=outlet_category_table.pk ";
            sql += "  LEFT JOIN outlet_brand_table ON outlet_table.brand_pk=outlet_brand_table.pk WHERE outlet_table.pk=? ";
        }
        db.query(sql, [pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                if (categoryToNumber(table) != -1) {
                    return response(req, res, 100, "success", result[0])
                } else {
                    return response(req, res, 100, "success", result[0])
                }
            }
        })

    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const addNoteImage = (req, res) => {
    try {
        if (req.file) {
            return response(req, res, 100, "success", { filename: `/image/note/${req.file.filename}` })
        } else {
            return response(req, res, -100, "이미지가 비어 있습니다.", [])
        }
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const getItems = (req, res) => {
    try {
        console.log(1)
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        let { table, level, category_pk, brand_pk, status, user_pk, keyword, keyword_columns, limit, page, page_cut, order } = (req.query.table ? { ...req.query } : undefined) || (req.body.table ? { ...req.body } : undefined);
        let sql = `SELECT * FROM ${table}_table `;
        let pageSql = `SELECT COUNT(*) FROM ${table}_table `;

        let whereStr = " WHERE 1=1 ";
        if (level) {
            if (level == 0) {
                whereStr += ` AND user_level=${level} `;

            } else {
                whereStr += ` AND user_level>=${level} `;

            }
        }
        if (category_pk) {
            whereStr += ` AND category_pk=${category_pk} `;
        }
        if (brand_pk) {
            whereStr += ` AND brand_pk=${brand_pk} `;
        }
        if (status) {
            whereStr += ` AND status=${status} `;
        }
        if (user_pk) {
            whereStr += ` AND user_pk=${user_pk} `;
        }

        if (table == 'coupon') {
            sql = "SELECT coupon_table.*, (price - sell_price) AS discount_price ,coupon_category_table.name AS category_name,coupon_brand_table.name AS brand_name from ";
            sql += " coupon_table LEFT JOIN coupon_category_table ON coupon_table.category_pk=coupon_category_table.pk ";
            sql += "  LEFT JOIN coupon_brand_table ON coupon_table.brand_pk=coupon_brand_table.pk ";
        }
        if (table == 'outlet') {
            sql = "SELECT outlet_table.*, outlet_category_table.name AS category_name,outlet_brand_table.name AS brand_name from ";
            sql += " outlet_table LEFT JOIN outlet_category_table ON outlet_table.category_pk=outlet_category_table.pk ";
            sql += "  LEFT JOIN outlet_brand_table ON outlet_table.brand_pk=outlet_brand_table.pk ";
        }
        if (table == 'log_manager_action') {
            sql = "SELECT log_manager_action_table.*, user_table.id AS user_id, user_table.name AS user_name FROM ";
            sql += " log_manager_action_table LEFT JOIN user_table ON log_manager_action_table.user_pk=user_table.pk ";
        }
        if (table == 'log_star' || table == 'log_point' || table == 'log_randombox' || table == 'log_esgw') {
            sql = `SELECT ${table}_table.*, user_table.id AS user_id, user_table.name AS user_name FROM `;
            sql += ` ${table}_table LEFT JOIN user_table ON ${table}_table.user_pk=user_table.pk`;
            if (decode.user_level < 40) {
                whereStr += `AND user_pk=${decode.pk}`;
            }
        }
        if(table=='exchange'){
            pageSql = 'SELECT COUNT(*) FROM log_star_table ';
            sql = `SELECT log_star_table.*, user_table.id AS user_id, user_table.name AS user_name, user_table.bank_name, user_table.account_number, user_table.account_name FROM `;
            sql += ` log_star_table LEFT JOIN user_table ON log_star_table.user_pk=user_table.pk`;
            whereStr += `AND log_star_table.type=4`;
        }
        if (table == 'log_withdraw') {
            sql = "SELECT log_star_table.*, user_table.id AS user_id, user_table.name AS user_name FROM ";
            sql += " log_star_table LEFT JOIN user_table ON log_star_table.user_pk=user_table.pk ";
            whereStr += ` AND log_star_table.type=4 `;
        }
        if (keyword) {
            whereStr += " AND (";
            for (var i = 0; i < keyword_columns.length; i++) {
                whereStr += ` ${i != 0 ? 'OR' : ''} ${keyword_columns[i]} LIKE '%${keyword}%' `;
            }
            whereStr += ")";
        }
        if (!page_cut) {
            page_cut = 10;
        }
        pageSql = pageSql + whereStr;
        sql = sql + whereStr + ` ORDER BY ${order ? order : 'pk'} DESC `;
        if (limit && !page) {
            sql += ` LIMIT ${limit} `;
        }
        if (page) {

            sql += ` LIMIT ${(page - 1) * page_cut}, ${page_cut}`;
            db.query(pageSql, async (err, result1) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    await db.query(sql, (err, result2) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "서버 에러 발생", [])
                        } else {
                            let maxPage = result1[0]['COUNT(*)'] % page_cut == 0 ? (result1[0]['COUNT(*)'] / page_cut) : ((result1[0]['COUNT(*)'] - result1[0]['COUNT(*)'] % page_cut) / page_cut + 1);
                            return response(req, res, 100, "success", { data: result2, maxPage: maxPage });
                        }
                    })
                }
            })
        } else {
            db.query(sql, (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    return response(req, res, 100, "success", result)
                }
            })
        }
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getSetting = (req, res) => {
    try {
        db.query("SELECT * FROM setting_table ORDER BY pk DESC LIMIT 1", (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", result[0])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const addSetting = (req, res) => {
    try {
        const image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        db.query("INSERT INTO setting_table (main_img) VALUES (?)", [image], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateSetting = (req, res) => {
    try {
        const pk = req.body.pk;
        const image = '/image/' + req.file.fieldname + '/' + req.file.filename;
        db.query("UPDATE setting_table SET main_img=? WHERE pk=?", [image, pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    }
    catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateStatus = (req, res) => {
    try {
        const { table, pk, num, column } = req.body;
        db.query(`UPDATE ${table}_table SET ${column}=? WHERE pk=? `, [num, pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", [])
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const onTheTopItem = (req, res) => {
    try {
        const { table, pk } = req.body;
        db.query(`SHOW TABLE STATUS LIKE '${table}_table' `, async (err, result1) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                let ai = result1[0].Auto_increment;
                await db.query(`UPDATE ${table}_table SET sort=? WHERE pk=? `, [ai, pk], async (err, result2) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버 에러 발생", [])
                    } else {
                        await db.query(`ALTER TABLE ${table}_table AUTO_INCREMENT=?`, [ai + 1], (err, result3) => {
                            if (err) {
                                console.log(err)
                                return response(req, res, -200, "서버 에러 발생", [])
                            } else {
                                return response(req, res, 100, "success", [])
                            }
                        })
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const changeItemSequence = (req, res) => {
    try {
        const { pk, sort, table, change_pk, change_sort } = req.body;
        let date = new Date();
        date = parseInt(date.getTime() / 1000);

        let sql = `UPDATE ${table}_table SET sort=${change_sort} WHERE pk=?`;
        let settingSql = "";
        if (sort > change_sort) {
            settingSql = `UPDATE ${table}_table SET sort=sort+1 WHERE sort < ? AND sort >= ? AND pk!=? `;
        } else if (change_sort > sort) {
            settingSql = `UPDATE ${table}_table SET sort=sort-1 WHERE sort > ? AND sort <= ? AND pk!=? `;
        } else {
            return response(req, res, -100, "둘의 값이 같습니다.", [])
        }
        db.query(sql, [pk], async (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                await db.query(settingSql, [sort, change_sort, pk], async (err, result) => {
                    if (err) {
                        console.log(err)
                        return response(req, res, -200, "서버 에러 발생", [])
                    } else {
                        return response(req, res, 100, "success", [])
                    }
                })
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

const getDailyPercent = (req, res) => {
    try {
        db.query('SELECT * FROM daily_percentage_table', (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            } else {
                return response(req, res, 100, "success", result[0]);
            }
        })
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const updateDailyPercent = (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -200, "권한이 없습니다.", [])
        } else {
            const { type_percent, money, money_percent, date, pk } = req.body;
            db.query('UPDATE daily_percentage_table SET type_percent=?, money=?, money_percent=?, date=? WHERE pk=?', [type_percent, money, money_percent, date, pk], (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    return response(req, res, 100, "success", []);
                }
            })
        }

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}

module.exports = {
    onLoginById, getUserToken, onLogout, checkExistId, checkExistNickname, sendSms, kakaoCallBack, editMyInfo, uploadProfile,//auth
    getUsers, getItems, getItem, getHomeContent, getSetting, getVideo, findIdByPhone, findAuthByIdAndPhone, getComments, getCommentsManager, getDailyPercent, getAddressByText, getAllDataByTables, getGenealogy, getUserMoney,//select
    addMaster, onSignUp, addItem, addNoteImage, addSetting, addComment, addAlarm,//insert 
    updateUser, updateItem, updateMaster, updateSetting, updateStatus, onTheTopItem, changeItemSequence, changePassword, updateComment, updateAlarm, updateDailyPercent, updateUserMoneyByManager, lotteryDailyPoint,//update
    deleteItem,
    requestWithdraw, onGift, registerRandomBox, buyESGWPoint, subscriptionDeposit, onOutletOrder
};