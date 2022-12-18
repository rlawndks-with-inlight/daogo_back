const express = require('express')
//const { json } = require('body-parser')
const router = express.Router()
const cors = require('cors')
router.use(cors())
router.use(express.json())
const { _ } = require('lodash');
const crypto = require('crypto')
//const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const { checkLevel, getSQLnParams, getUserPKArrStrWithNewPK,
    isNotNullOrUndefined, namingImagesPath, nullResponse, getKewordListBySchema,
    lowLevelResponse, response, removeItems, returnMoment, formatPhoneNumber,
    categoryToNumber, sendAlarm, updateUserTier, getDailyPercentReturn, queryPromise, max_child_depth,
    getEventRandomboxPercentByTier, getDiscountPoint, commarNumber, makeMaxPage, discountOutletList, discountOutlet, getMonday
} = require('../util')
const {
    getRowsNumWithKeyword, getRowsNum, getAllDatas,
    getDatasWithKeywordAtPage, getDatasAtPage,
    getKioskList, getItemRows, getItemList, dbQueryList, dbQueryRows, insertQuery, getTableAI
} = require('../query-util')
const macaddress = require('node-macaddress');
var ip = require("ip");
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
                                let payment_pw = await makeHash('0000');
                                payment_pw = payment_pw?.data

                                sql = 'INSERT INTO user_table (id, pw, name, nickname , phone, user_level, parent_id, parent_pk, depth, payment_pw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
                                if (parent_result[0]) {
                                    depth = parent_result[0]?.depth + 1;
                                }
                                await db.query(sql, [id, hash, name, nickname, phone, user_level, parent_result[0]?.id ?? "", parent_result[0]?.pk ?? 0, depth, payment_pw], async (err, result) => {

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
                                requestIp = ip.address();
                                console.log(ip.address())
                                console.log(req.headers['x-forwarded-for'])
                                console.log(req.connection.remoteAddress)
                                console.log(req.ip)
                                requestIp = requestIp.replaceAll('::ffff:', '');
                                let result1_ = await insertQuery('UPDATE user_table SET last_login=? WHERE pk=?', [returnMoment(), result1[0].pk]);
                                let result2_ = await insertQuery('INSERT INTO log_login_table (ip, user_level, user_id, user_name) VALUES (?, ?, ?, ?)', [requestIp, result1[0].user_level, result1[0].id, result1[0].name]);
                                let is_user_lottery_today = await dbQueryList(`SELECT * FROM log_randombox_table WHERE DATE_FORMAT(date,'%Y-%m-%d') = '${returnMoment().substring(0, 10)}' AND user_pk=${result1[0].pk} AND type=7`)
                                let user_money = await getUserMoneyReturn(result1[0]?.pk);
                                if (is_user_lottery_today?.result?.length > 0 || user_money?.randombox <= 0) {
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
const initializationIdCard = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        const { pk } = req.body;
        let url = "";
        db.query("UPDATE user_table SET profile_img=? WHERE pk=?", [url, pk], (err, result) => {
            if (err) {
                console.log(err)
                return response(req, res, -200, "서버 에러 발생", [])
            }
            else {
                return response(req, res, 200, "success", [])
            }
        })
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getUserMoney = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0)
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
        if (req?.query?.type == 'randomboxregister') {
            sql_list.push({ table: "star_to_randombox", sql: `SELECT SUM(price) AS star_to_randombox FROM log_star_table WHERE user_pk=${pk} AND type=2 ` })
        }
        if (req?.query?.type == 'withdrawrequest') {
            sql_list.push({ table: "withdraw_setting", sql: `SELECT * FROM setting_table ORDER BY pk DESC LIMIT 1`, type: 'obj' })
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
            if ((await result[i])?.table == 'user' || (await result[i])?.table == 'withdraw_setting') {
                obj[(await result[i])?.table] = { ...(await result[i])?.data[0] };
            } else {
                obj[(await result[i])?.table] = (await result[i])?.data[0][(await result[i])?.table] ?? 0;
            }
        }
        return response(req, res, 100, "success", obj);
    } catch (e) {
        console.log(e)
        return response(req, res, -200, "서버 에러 발생", []);
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
            // if (negative_result) {
            //     await db.rollback();
            //     return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
            // }
            await updateUserTier(pk);
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
const updateUserSubscriptionDepositByManager = async (req, res) => {//관리자가 유저 청약예치금 변동 시
    try {
        const decode = checkLevel(req.cookies.token, 40)
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", []);
        }
        await db.beginTransaction();
        let { pk, reason_correction, manager_note, edit_list } = req.body;
        let explain_obj = JSON.stringify({
            manager_pk: decode?.pk,
            manager_id: decode.id
        })
        if (edit_list?.length > 0) {
            for (var i = 0; i < edit_list?.length; i++) {
                let result1 = await insertQuery(`INSERT INTO log_${edit_list[i]?.type}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                    [edit_list[i]?.price * (-1), pk, 8, edit_list[i]?.note, explain_obj])
                let result2 = await insertQuery(`INSERT INTO log_${edit_list[i]?.type}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                    [edit_list[i]?.price, pk, 5, "관리자의 청약예치금 수정에 의한 반환", explain_obj])
            }
            let user_money = await getUserMoneyReturn(pk);
            let negative_result = await checkUserPointNegative(user_money);
            // if (negative_result) {
            //     await db.rollback();
            //     return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
            // }
            await updateUserTier(pk);
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
        if (user_money?.randombox <= 0) {
            return response(req, res, -100, "랜덤박스 포인트를 보유하고 있지 않습니다.", []);
        }
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
        let point = 0;
        if ((randombox_point * parseFloat(daily_percent?.type_percent?.point)) / 100 - parseInt((randombox_point * parseFloat(daily_percent?.type_percent?.point)) / 100) < 0.5) {//내림
            point = parseInt((randombox_point * parseFloat(daily_percent?.type_percent?.point)) / 100);
        } else {//올림
            point = parseInt((randombox_point * parseFloat(daily_percent?.type_percent?.point)) / 100) + 1;
        }
        let star = 0;
        if ((randombox_point * parseFloat(daily_percent?.type_percent?.star)) / 100 - parseInt((randombox_point * parseFloat(daily_percent?.type_percent?.star)) / 100) < 0.5) {//내림
            star = parseInt((randombox_point * parseFloat(daily_percent?.type_percent?.star)) / 100);
        } else {//올림
            star = parseInt((randombox_point * parseFloat(daily_percent?.type_percent?.star)) / 100) + 1;
        }
        let log_list = [{ table: 'randombox', price: randombox_point * (-1), user_pk: decode?.pk, type: 7 },
        { table: 'point', price: point, user_pk: decode?.pk, type: 7 },
        { table: 'star', price: star, user_pk: decode?.pk, type: 7 }];
        let explain_obj = {
            percent: parseFloat(daily_percent?.money[idx])
        }
        explain_obj = JSON.stringify(explain_obj)

        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, 7, "", explain_obj])
        }
        await updateUserTier(decode?.pk);
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
        let { receiver_id, receiver_phone, send_star, send_point, send_esgw, payment_pw } = req.body;
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
        if ((send_star < 0 && send_star) || (send_point < 0 && send_point) || (send_esgw < 0 && send_esgw)) {
            return response(req, res, -100, "0 이상의 숫자를 입력해주세요.", []);
        }
        let log_list = [];
        if (send_star && send_star > 0) {
            log_list.push({ table: 'star', price: send_star * (-1), user_pk: decode?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: receiver_user?.pk, user_id: receiver_user?.id, user_name: receiver_user?.name }) })
            log_list.push({ table: 'star', price: send_star * (97 / 100), user_pk: receiver_user?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: decode?.pk, user_id: decode?.id, user_name: decode?.name }) })
        }
        if (send_point && send_point > 0) {
            log_list.push({ table: 'point', price: send_point * (-1), user_pk: decode?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: receiver_user?.pk, user_id: receiver_user?.id, user_name: receiver_user?.name }) })
            log_list.push({ table: 'point', price: send_point * (97 / 100), user_pk: receiver_user?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: decode?.pk, user_id: decode?.id, user_name: decode?.name }) })
        }
        if (send_esgw && send_esgw > 0) {
            log_list.push({ table: 'esgw', price: send_esgw * (-1), user_pk: decode?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: receiver_user?.pk, user_id: receiver_user?.id, user_name: receiver_user?.name }) })
            log_list.push({ table: 'esgw', price: send_esgw * (97 / 100), user_pk: receiver_user?.pk, type: 3, explain_obj: JSON.stringify({ user_pk: decode?.pk, user_id: decode?.id, user_name: decode?.name }) })
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
        await updateUserTier(decode?.pk);
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
        let parent_user_list = await getParentUserList(decode)
        for (var i = 0; i < parent_user_list?.length; i++) {
            if (parent_user_list[i]?.pay_user_count >= 10 && (decode?.depth - parent_user_list[i]?.depth <= 15)) {
                if (parent_user_list[i]?.tier > 0) {
                    log_list.push({ table: 'randombox', price: star * (getEventRandomboxPercentByTier(parent_user_list[i]?.tier) / 100), user_pk: parent_user_list[i]?.pk, type: 11 });
                }
            } else if (parent_user_list[i]?.pay_user_count >= 5 && (decode?.depth - parent_user_list[i]?.depth <= 10)) {
                if (parent_user_list[i]?.tier > 0) {
                    log_list.push({ table: 'randombox', price: star * (getEventRandomboxPercentByTier(parent_user_list[i]?.tier) / 100), user_pk: parent_user_list[i]?.pk, type: 11 });
                }
            } else if (parent_user_list[i]?.pay_user_count >= 3 && (decode?.depth - parent_user_list[i]?.depth <= 5)) {
                if (parent_user_list[i]?.tier > 0) {
                    log_list.push({ table: 'randombox', price: star * (getEventRandomboxPercentByTier(parent_user_list[i]?.tier) / 100), user_pk: parent_user_list[i]?.pk, type: 11 });
                }
            } else if (parent_user_list[i]?.pay_user_count >= 1 && (decode?.depth - parent_user_list[i]?.depth <= 2)) {
                if (parent_user_list[i]?.tier > 0) {
                    log_list.push({ table: 'randombox', price: star * (getEventRandomboxPercentByTier(parent_user_list[i]?.tier) / 100), user_pk: parent_user_list[i]?.pk, type: 11 });
                }
            } else {

            }
        }
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj) VALUES (?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", ""])
        }
        let user_money = await getUserMoneyReturn(decode?.pk);
        let negative_result = await checkUserPointNegative(user_money);
        if (negative_result) {
            await db.rollback();
            return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
        }
        for (var i = 0; i < log_list?.length; i++) {
            await updateUserTier(log_list[i]?.user_pk);
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
        let withdraw_setting = await dbQueryList(`SELECT * FROM setting_table ORDER BY pk DESC LIMIT 1`);
        withdraw_setting = withdraw_setting?.result[0];
        let moment_time = returnMoment().substring(11, 16);
        if (moment_time >= withdraw_setting?.withdraw_start_time && moment_time <= withdraw_setting?.withdraw_end_time) {

        } else {
            return response(req, res, -100, `출금 시간이 아닙니다. \n출금가능시간: ${withdraw_setting?.withdraw_start_time} ~ ${withdraw_setting?.withdraw_end_time}`, []);
        }

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


        console.log(withdraw_setting)
        if (star > withdraw_setting[`withdraw_${user?.tier}`]) {
            return response(req, res, -100, `최대 출금 신청 금액은 수수료 제외 ${commarNumber(withdraw_setting[`withdraw_${user?.tier}`])} 스타 입니다.`, []);
        }
        withdraw_commission_percent = withdraw_setting?.withdraw_commission_percent;
        let log_list = [
            { table: 'star', price: (star + star * withdraw_commission_percent / 100) * (-1), user_pk: decode?.pk, type: 4 },
        ]
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj, status) VALUES (?, ?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", JSON.stringify({ withdraw_commission_percent: withdraw_commission_percent, receipt_won: star * 100, star: star }), 0])//0-출금전, 1-출금완료
        }
        let user_money = await getUserMoneyReturn(decode?.pk);
        let negative_result = await checkUserPointNegative(user_money);
        if (negative_result) {
            await db.rollback();
            return response(req, res, -200, "유저의 금액은 마이너스가 될 수 없습니다.", []);
        }
        await updateUserTier(decode?.pk);
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
            { table: 'esgw', price: point / 5, user_pk: decode?.pk, type: 9 },
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
        await updateUserTier(decode?.pk);
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
        let money_category = [{ category: 'star', kor: '스타', max: 60000 }, { category: 'esgw', kor: 'ESGW 포인트', max: 30000 }, { category: 'point', kor: '포인트', max: 10000 }];
        let user_subscriptiondeposit_sql = "SELECT pk";
        for (var i = 0; i < money_category.length; i++) {
            user_subscriptiondeposit_sql += `, (SELECT SUM(price) FROM log_${money_category[i].category}_table WHERE user_pk=${decode?.pk} AND type=8) AS ${money_category[i].category} `
        }
        user_subscriptiondeposit_sql += ` FROM user_table WHERE pk=${decode?.pk} `;
        let user_subscriptiondeposit = await dbQueryList(user_subscriptiondeposit_sql);
        user_subscriptiondeposit = user_subscriptiondeposit?.result[0];
        for (var i = 0; i < money_category.length; i++) {
            if (user_subscriptiondeposit[money_category[i].category] * (-1) > money_category[i].max) {
                await db.rollback();
                return response(req, res, -100, `${money_category[i].kor}가 가능한 청약예치금 금액을 초과 하였습니다.`, []);
            }
        }
        await updateUserTier(decode?.pk);
        await db.commit();
        return response(req, res, 100, "success", []);
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const isExistUserParent = async (parent_pk, child_pk, user_obj) => {
    let bool = false;
    let current_user = { ...user_obj[child_pk] };
    let prider_count = 0;//중간에 프라이더 수
    if (child_pk == parent_pk) {
        return {
            bool: true,
            prider_count: 0
        };
    } else {
        while (1) {
            if (current_user['parent_pk'] == parent_pk) {
                bool = true;
                break;
            } else {
                if (!user_obj[current_user['parent_pk']]) {
                    break;
                } else {
                    if (user_obj[current_user['parent_pk']]?.prider > 0) {
                        prider_count++;
                    }
                    current_user = { ...user_obj[current_user['parent_pk']] };
                }
            }
        }
        return {
            bool: bool,
            prider_count: prider_count
        };
    }
}
const getWeekSettleChild = async (req, res) => {//이번주 산하 유저의 매출액
    try {
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let { pk, page } = req.query;
        let monday = returnMoment(getMonday(new Date())).substring(0, 10) + ' 00:00:00';
        let sql = "";
        sql = "SELECT log_randombox_table.*, u_u.id AS user_id, u_u.name AS user_name, m_u.id AS manager_id, m_u.name AS manager_name  FROM ";
        sql += " log_randombox_table LEFT JOIN user_table u_u ON log_randombox_table.user_pk=u_u.pk ";
        sql += `  LEFT JOIN user_table m_u ON log_randombox_table.manager_pk=m_u.pk  WHERE log_randombox_table.type=10 AND log_randombox_table.date >= '${monday}'`;
        let settle_list = await dbQueryList(sql);
        settle_list = settle_list?.result;
        let user_list = await dbQueryList(`SELECT pk, parent_pk, depth, prider FROM user_table WHERE user_level=0 ORDER BY pk DESC`);
        user_list = user_list?.result;
        let user_obj = {};
        for (var i = 0; i < user_list.length; i++) {
            user_obj[user_list[i]?.pk] = user_list[i];
        }
        let result = [];
        for (var i = 0; i < settle_list.length; i++) {
            let bool = await isExistUserParent(pk, settle_list[i].user_pk, user_obj);
            if (bool?.bool) {
                result.push(settle_list[i]);
            }
        }
        let maxPage = makeMaxPage(result.length, 20);
        result = result.slice((page - 1) * 20, page * 20);
        let user = await dbQueryList(`SELECT id, name FROM user_table WHERE pk=${pk}`);
        user = user?.result[0];
        return response(req, res, 100, "success", { user: user, data: result, maxPage: maxPage });
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}

const onWeekSettle = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let monday = returnMoment(getMonday(new Date())).substring(0, 10) + ' 00:00:00';
        let sql = "";
        sql = "SELECT log_randombox_table.*, u_u.id AS user_id, u_u.name AS user_name, m_u.id AS manager_id, m_u.name AS manager_name  FROM ";
        sql += " log_randombox_table LEFT JOIN user_table u_u ON log_randombox_table.user_pk=u_u.pk ";
        sql += `  LEFT JOIN user_table m_u ON log_randombox_table.manager_pk=m_u.pk  WHERE log_randombox_table.type=10 AND log_randombox_table.date >= '${monday}'`;
        let settle_list = await dbQueryList(sql);
        settle_list = settle_list?.result;//이번주 매출 리스트
        let user_list = await dbQueryList("SELECT pk, parent_pk, depth, prider FROM user_table");//유저리스트
        user_list = user_list?.result;
        let user_obj = {};
        for (var i = 0; i < user_list.length; i++) {
            user_obj[user_list[i]?.pk] = user_list[i];
        }
        let prider_list = await dbQueryList("SELECT * FROM user_table WHERE prider=2 ");//프라이더 리스트
        prider_list = prider_list?.result;
        let get_price_by_tier = { 0: 0, 5: 360000, 10: 1200000, 15: 3600000, 20: 6000000, 25: 12000000 };
        let log_list = [];

        for (i = 0; i < prider_list.length; i++) {
            prider_list[i]['settle'] = 0;
            for (var j = 0; j < settle_list.length; j++) {
                let bool = await isExistUserParent(prider_list[i]?.pk, settle_list[j].user_pk, user_obj);
                if (bool?.bool) {
                    let settle_obj = JSON.parse(settle_list[j]?.explain_obj);
                    if (bool?.prider_count >= 2) {
                        prider_list[i]['settle'] += get_price_by_tier[settle_obj['tier']] / 10000 * 0;
                    } else if (bool?.prider_count == 1) {
                        prider_list[i]['settle'] += get_price_by_tier[settle_obj['tier']] / 10000 * 0.5;
                    } else if (bool?.prider_count == 0) {
                        prider_list[i]['settle'] += get_price_by_tier[settle_obj['tier']] / 10000 * 3;
                    }
                }
            }
            if (prider_list[i]['settle'] > 0) {
                log_list.push({ table: 'star', price: prider_list[i]['settle'], user_pk: prider_list[i]?.pk, type: 15 })
            }
        }
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj, manager_pk) VALUES (?, ?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", "{}", decode?.pk])
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
const addMarketing = async (req, res) => {//매출등록
    try {
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        const { id, marketing } = req.body;
        let is_exist_user = await dbQueryList(`SELECT * FROM user_table WHERE id='${id}'`, [])
        if (is_exist_user?.result.length <= 0) {
            return response(req, res, -100, "유저가 존재하지 않습니다.", []);
        }
        is_exist_user = is_exist_user?.result[0];

        let parent_user = await dbQueryList(`SELECT * FROM user_table WHERE pk=${is_exist_user?.parent_pk} AND user_level=0`);
        parent_user = parent_user?.result[0];
        let marketing_list = [
            { price: 36, randombox: 9000, introduce_percent: 6 },
            { price: 120, randombox: 30000, introduce_percent: 7 },
            { price: 360, randombox: 90000, introduce_percent: 8 },
            { price: 600, randombox: 150000, introduce_percent: 9 },
            { price: 1200, randombox: 300000, introduce_percent: 10 }
        ];
        let log_list = []
        let introduce_price = 0;
        for (var i = 0; i < marketing_list.length; i++) {
            if (marketing_list[i]?.price == marketing) {
                log_list.push({ table: 'randombox', price: marketing_list[i]?.randombox, user_pk: is_exist_user?.pk, type: 10, explain_obj: JSON.stringify({ tier: (i + 1) * 5 }) });
                introduce_price = marketing_list[i]?.price * 10;
                break;
            }
        }
        if (i == marketing_list.length) {
            return response(req, res, -100, "매출 등급 에러 발생", []);
        }
        for (var i = 0; i < marketing_list.length; i++) {
            if (parent_user?.tier / 5 == i + 1) {
                log_list.push({ table: 'star', price: introduce_price * (marketing_list[i]?.introduce_percent / 10) * 0.8, user_pk: parent_user?.pk, type: 10, explain_obj: JSON.stringify({ introduced_pk: is_exist_user?.pk, introduced_id: is_exist_user?.id, introduced_name: is_exist_user?.name }) });
                log_list.push({ table: 'point', price: introduce_price * (marketing_list[i]?.introduce_percent / 10) * 0.2, user_pk: parent_user?.pk, type: 10, explain_obj: JSON.stringify({ introduced_pk: is_exist_user?.pk, introduced_id: is_exist_user?.id, introduced_name: is_exist_user?.name }) });
                break;
            }
        }
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj, manager_pk) VALUES (?, ?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", log_list[i]?.explain_obj, decode?.pk])//0-출금전, 1-출금완료
        }
        await updateUserTier(is_exist_user?.pk);
        await db.commit();
        return response(req, res, 100, "success", []);
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const onOutletOrder = async (req, res) => {//아울렛 구매
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let { request, name, phone, zip_code, address, address_detail, refer, payment_pw, item_pk, use_point, item_count } = req.body;
        let user = await dbQueryList(`SELECT * FROM user_table WHERE pk=${decode?.pk}`);
        user = user?.result[0];
        let insert_payment_pw = await makeHash(payment_pw);
        if (insert_payment_pw?.data !== user?.payment_pw) {
            return response(req, res, -100, "결제 비밀번호가 틀렸습니다.", []);
        }
        let introduce_percent_obj_by_tier = { 0: 5, 5: 6, 10: 7, 15: 8, 20: 9, 25: 10 };//할인율

        let item = await dbQueryList(`SELECT * FROM outlet_table WHERE pk=${item_pk}`);
        item = item?.result[0];
        let user_money_ = await getUserMoneyReturn(decode?.pk);
        let purchase_list = [];
        let log_list = [];
        let discount_price = getDiscountPoint(item?.sell_star, item?.is_use_point, item?.point_percent, user?.tier) * item_count;
        // 스타 인설트
        //자기 위에 회원 포인트 받기
        //자신 랜덤박스 포인트 받기, 포인트 깎이기
        let point = 0;
        let use_star_money = 0;
        if (use_point) {
            if (user_money_?.point < discount_price) {
                point = user_money_?.point;
            } else {
                point = discount_price;
            }
            use_star_money = (item?.sell_star * item_count - point - discountOutlet(item?.sell_star * item_count, user?.tier));
            purchase_list.push({
                table: 'star', price: (item?.sell_star * item_count - point - discountOutlet(item?.sell_star * item_count, user?.tier)) * (-1), user_pk: decode?.pk, type: 0, item_pk: item?.pk, explain_obj: JSON.stringify({
                    request: request,
                    name: name,
                    phone: phone,
                    zip_code: zip_code,
                    address: address,
                    address_detail: address_detail,
                    refer: refer,
                    point: point,
                    count: item_count,
                })
            })
        } else {
            use_star_money = (item?.sell_star * item_count - discountOutlet(item?.sell_star * item_count, user?.tier));
            purchase_list.push({
                table: 'star', price: (item?.sell_star * item_count - discountOutlet(item?.sell_star * item_count, user?.tier)) * (-1), user_pk: decode?.pk, type: 0, item_pk: item?.pk, explain_obj: JSON.stringify({
                    request: request,
                    name: name,
                    phone: phone,
                    zip_code: zip_code,
                    address: address,
                    address_detail: address_detail,
                    refer: refer,
                    point: 0,
                    count: item_count,
                })
            })
        }
        await db.beginTransaction();
        let insert_star_pk = 0;

        for (var i = 0; i < purchase_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${purchase_list[i]?.table}_table (price, user_pk, type, note, explain_obj, item_pk, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [purchase_list[i]?.price, purchase_list[i]?.user_pk, purchase_list[i]?.type, "", purchase_list[i]?.explain_obj, purchase_list[i]?.item_pk, 0]);
            if (purchase_list[i]?.table == 'star') {
                insert_star_pk = result?.result?.insertId;
            }
        }
        if (use_point) {//포인트 사용 시 포인트 깎이기
            log_list.push({
                table: 'point', price: point * (-1), user_pk: decode?.pk, type: 0, item_pk: item?.pk, explain_obj: JSON.stringify({
                    request: request,
                    name: name,
                    phone: phone,
                    zip_code: zip_code,
                    address: address,
                    address_detail: address_detail,
                    refer: refer,
                    count: item_count,
                    star_pk: insert_star_pk
                })
            })
        }
        if (item?.randombox_point > 0) {//랜덤박스 포인트 지급 받을 시 랜덤박스 지급 받음
            log_list.push({
                table: 'randombox', price: item?.randombox_point * item_count, user_pk: decode?.pk, type: 13, item_pk: item?.pk, explain_obj: JSON.stringify({
                    request: request,
                    name: name,
                    phone: phone,
                    zip_code: zip_code,
                    address: address,
                    address_detail: address_detail,
                    refer: refer,
                    count: item_count,
                    star_pk: insert_star_pk
                })
            })
        }
        let parent_list = await getParentUserList(decode);
        if (parent_list[0]?.tier > user?.tier) {
            log_list.push({
                table: 'randombox', price: use_star_money * ((introduce_percent_obj_by_tier[parent_list[0]?.tier] - introduce_percent_obj_by_tier[user?.tier]) / 100) * item_count, user_pk: parent_list[0]?.pk, type: 12, item_pk: item?.pk, explain_obj: JSON.stringify({
                    item_pk: item?.pk,
                    item_name: item?.name,
                    user_pk: decode?.pk,
                    user_id: decode?.id,
                    star_pk: insert_star_pk
                })
            })
        }

        let insert_point_pk = 0;

        let star_log = await dbQueryList(`SELECT * FROM log_star_table WHERE pk=${insert_star_pk}`);
        star_log = star_log?.result[0];
        let star_explain_obj = JSON.parse(star_log?.explain_obj);
        star_explain_obj['point_pk'] = insert_point_pk;
        let star_update = await insertQuery("UPDATE log_star_table SET explain_obj=? WHERE pk=?", [JSON.stringify(star_explain_obj), insert_star_pk]);
        if (insert_point_pk != 0) {
            let point_log = await dbQueryList(`SELECT * FROM log_point_table WHERE pk=${insert_point_pk}`);
            point_log = point_log?.result[0];
            let point_explain_obj = JSON.parse(point_log?.explain_obj);
            point_explain_obj['star_pk'] = insert_star_pk;
            let point_update = await insertQuery("UPDATE log_point_table SET explain_obj=? WHERE pk=?", [JSON.stringify(point_explain_obj), insert_point_pk]);
        }

        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj, item_pk) VALUES (?, ?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", log_list[i]?.explain_obj, log_list[i]?.item_pk])//
        }
        await updateUserTier(parent_list[0]?.pk);
        let user_money = await getUserMoneyReturn(decode?.pk);
        let negative_result = await checkUserPointNegative(user_money);
        if (negative_result) {
            await db.rollback();
            return response(req, res, -200, "잔액이 부족합니다.", []);
        }
        await updateUserTier(decode?.pk);
        await db.commit();
        return response(req, res, 100, "success", []);
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const onChangeExchangeStatus = async (req, res) => {//출금신청 관리
    try {
        const { pk, status } = req.body;
        console.log(req.body);
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let star_log = await dbQueryList(`SELECT * FROM log_star_table WHERE pk=${pk}`);
        star_log = star_log?.result[0];
        let explain_obj = JSON.parse(star_log['explain_obj']);
        await db.beginTransaction();
        let sql = "UPDATE log_star_table SET status=? ";
        let values = [];
        values.push(status);
        if (status == -1 || status == 1) {
            sql += ", manager_pk=? ";
            values.push(decode?.pk);
            if (status == -1) {//다시 지급
                let log_list = [{ table: 'star', price: star_log?.price * (-1), user_pk: star_log?.user_pk, type: 4, manager_pk: decode?.pk }];
                for (var i = 0; i < log_list?.length; i++) {
                    let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj, manager_pk, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                        [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", JSON.stringify({}), log_list[i]?.manager_pk, -1])//
                }

            }
        } else if (status == 2) {
            if (star_log?.manager_pk != decode?.pk) {
                return response(req, res, -100, "담당자가 일치하지 않습니다.", []);
            }
        } else {
            return response(req, res, -100, "잘못된 값입니다.", []);
        }
        explain_obj['status'] = status;//상태
        explain_obj['date'] = returnMoment();//진행완료일

        sql += ", explain_obj=? ";
        values.push(JSON.stringify(explain_obj));
        sql += ` WHERE pk=? `;
        values.push(pk);
        let result = insertQuery(sql, values);
        await db.commit();
        return response(req, res, 100, "success", []);
    } catch (err) {
        console.log(err)
        await db.rollback();
        return response(req, res, -200, "서버 에러 발생", []);
    } finally {

    }
}
const onChangeOutletOrderStatus = async (req, res) => {//아울렛주문 관리
    try {
        const { pk, status, invoice, return_reason } = req.body;
        if (!pk || !status) {
            return response(req, res, -100, "필수값이 비어 있습니다.", []);
        }

        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let star_log = await dbQueryList(`SELECT * FROM log_star_table WHERE pk=${pk}`);
        star_log = star_log?.result[0];
        let sell_user = await dbQueryList(`SELECT * FROM user_table WHERE pk=${star_log?.user_pk}`);
        sell_user = sell_user?.result[0];
        let explain_obj = JSON.parse(star_log['explain_obj']);

        let sql = "UPDATE log_star_table SET status=? ";
        let values = [];
        values.push(status);
        await db.beginTransaction();
        let user_list = [star_log?.user_pk];

        if (status == -1 || status == 1) {
            sql += ",manager_pk=? ";
            values.push(decode?.pk);
            if (status == 1) {
                explain_obj['invoice'] = invoice;//송장
            } else {
                let log_list = [{ table: 'star', price: star_log?.price * (-1), user_pk: star_log?.user_pk, type: 0, manager_pk: decode?.pk, explain_obj: JSON.stringify({ point: explain_obj?.point }) }];
                let point_log = await dbQueryList(`SELECT * FROM log_point_table WHERE type=0 AND user_pk=${star_log?.user_pk} AND explain_obj LIKE '%star_pk":${pk}%'`);
                point_log = point_log?.result;
                let randombox_log = await dbQueryList(`SELECT * FROM log_randombox_table WHERE (type=12 OR type=13) AND explain_obj LIKE '%"star_pk":${pk}%'`);
                randombox_log = randombox_log?.result;
                for (var i = 0; i < point_log.length; i++) {
                    log_list.push({
                        table: 'point',
                        price: point_log[i]?.price * (-1),
                        user_pk: star_log?.user_pk,
                        type: 0,
                        manager_pk: decode?.pk,
                        explain_obj: JSON.stringify({})
                    })
                }
                for (var i = 0; i < randombox_log.length; i++) {
                    if (randombox_log[i]?.type == 13) {
                        user_list.push(randombox_log[i]?.user_pk);
                        log_list.push({
                            table: 'randombox',
                            price: randombox_log[i]?.price * (-1),
                            user_pk: randombox_log[i]?.user_pk,
                            type: randombox_log[i]?.type,
                            manager_pk: decode?.pk,
                            explain_obj: JSON.stringify({})
                        })
                    } else {
                        log_list.push({
                            table: 'randombox',
                            price: randombox_log[i]?.price * (-1),
                            user_pk: randombox_log[i]?.user_pk,
                            type: randombox_log[i]?.type,
                            manager_pk: decode?.pk,
                            explain_obj: JSON.stringify({ user_pk: star_log?.user_pk, user_id: sell_user?.id })
                        })
                    }
                }
                for (var i = 0; i < log_list?.length; i++) {
                    let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj, manager_pk, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                        [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", log_list[i]?.explain_obj, log_list[i]?.manager_pk, -1])//
                }
                explain_obj['return_reason'] = return_reason;//반송사유

            }
        } else if (status == 2) {
            if (star_log?.manager_pk != decode?.pk) {
                return response(req, res, -100, "담당자가 일치하지 않습니다.", []);
            }
        } else {
            return response(req, res, -100, "잘못된 값입니다.", []);
        }
        explain_obj['status'] = status;//상태
        explain_obj['date'] = returnMoment();//진행완료일

        sql += ", explain_obj=? ";
        values.push(JSON.stringify(explain_obj));
        sql += ` WHERE pk=? `;
        values.push(pk);
        let result = insertQuery(sql, values);
        for (var i = 0; i < user_list.length; i++) {
            await updateUserTier(user_list[i]);
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
const addMonthSettle = async (req, res) => {//월정산
    try {
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let { price, percent, user_prider_list } = req.body;
        console.log(req.body);
        if (!price || !percent || !user_prider_list) {
            return response(req, res, -100, "필수 값이 비어 있습니다.", []);
        }
        let user_list_sql = "SELECT * FROM user_table WHERE "
        for (var i = 0; i < user_prider_list.length; i++) {
            user_list_sql += ` prider=${user_prider_list[i]} OR`;
        }
        user_list_sql = user_list_sql.substring(0, user_list_sql.length - 2);
        let user_list = await dbQueryList(user_list_sql);
        user_list = user_list?.result;
        let log_list = [];
        for (var i = 0; i < user_list.length; i++) {
            log_list.push({ table: 'star', price: (price * percent / 10000 / (user_list.length)), user_pk: user_list[i]?.pk, type: 14 })
        }
        await db.beginTransaction();
        for (var i = 0; i < log_list?.length; i++) {
            let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (price, user_pk, type, note, explain_obj, manager_pk) VALUES (?, ?, ?, ?, ?, ?)`,
                [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, "", "{}", decode?.pk])
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
const insertUserMoneyByExcel = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다", []);
        }
        let { list } = req.body;

        let log_obj = {
            star: [],
            point: [],
            randombox: [],
            esgw: [],
        }
        let user_list_sql = `SELECT pk, id FROM user_table WHERE id IN (`;
        for (var i = 0; i < list.length; i++) {
            user_list_sql += `'${list[i][0]}',`
        }
        user_list_sql = user_list_sql.substring(0, user_list_sql.length - 1);
        user_list_sql += ")";
        let user_list = await dbQueryList(user_list_sql);
        user_list = user_list?.result;
        let user_obj = {};
        for (var i = 0; i < user_list.length; i++) {
            user_obj[user_list[i]['id']] = user_list[i];
        }
        if (list.length > 0) {
            for (var i = 0; i < list.length; i++) {
                if (!isNaN(parseFloat(list[i][2])) && list[i][2] && parseFloat(list[i][2]) != 0) {//스타
                    log_obj.star.push([parseFloat(list[i][2]), list[i][6], user_obj[list[i][0]]?.pk, 5, decode?.pk, "{}"]);//price, note, user_pk, type, manager_pk, explain_obj 
                }
                if (!isNaN(parseFloat(list[i][3])) && list[i][3] && parseFloat(list[i][3]) != 0) {//포인트
                    log_obj.point.push([parseFloat(list[i][3]), list[i][6], user_obj[list[i][0]]?.pk, 5, decode?.pk, "{}"]);
                }
                if (!isNaN(parseFloat(list[i][4])) && list[i][4] && parseFloat(list[i][4]) != 0) {//랜덤박스
                    log_obj.randombox.push([parseFloat(list[i][4]), list[i][6], user_obj[list[i][0]]?.pk, 5, decode?.pk, "{}"]);
                }
                if (!isNaN(parseFloat(list[i][5])) && list[i][5] && parseFloat(list[i][5]) != 0) {//esgw
                    log_obj.esgw.push([parseFloat(list[i][5]), list[i][6], user_obj[list[i][0]]?.pk, 5, decode?.pk, "{}"]);
                }
            }
            await db.beginTransaction();
            if (log_obj['star'].length > 0) {
                console.log(log_obj['star'])
                let star_result = await insertQuery(`INSERT INTO log_star_table (price, note, user_pk, type, manager_pk, explain_obj) VALUES ? `, [log_obj['star']]);
            }
            if (log_obj['point'].length > 0) {
                let point_result = await insertQuery(`INSERT INTO log_point_table (price, note, user_pk, type, manager_pk, explain_obj) VALUES ? `, [log_obj['point']]);
            }
            if (log_obj['randombox'].length > 0) {
                let randombox_result = await insertQuery(`INSERT INTO log_randombox_table (price, note, user_pk, type, manager_pk, explain_obj) VALUES ? `, [log_obj['randombox']]);
            }
            if (log_obj['esgw'].length > 0) {
                let esgw_result = await insertQuery(`INSERT INTO log_esgw_table (price, note, user_pk, type, manager_pk, explain_obj) VALUES ? `, [log_obj['esgw']]);
            }
            for (var i = 0; i < user_list.length; i++) {
                await updateUserTier(user_list[i]?.pk);
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
            let sell_outlet = await dbQueryList(`SELECT COUNT(*) AS sell_outlet FROM log_star_table WHERE user_pk=${decode?.pk} AND type=0 AND SUBSTR(date, 1, 7)='${returnMoment().substring(0, 7)}'`)
            let result = await dbQueryList(`SELECT * FROM user_table WHERE pk=${decode?.pk}`);
            if (result?.code > 0) {
                result = result?.result[0];
                result['sell_outlet'] = sell_outlet?.result[0];
                res.send(result);
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
const getMyPageContent = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", []);
        }
        let result_list = [];
        let obj = {};
        let sql_list = [
            // {table:"randombox",sql:""},
            //  {table:"star",sql:""},
            // {table:"point",sql:""},
            { table: "user", sql: `SELECT * FROM user_table WHERE pk=${decode?.pk}`, type: 'obj' },
            { table: "marketing", sql: `SELECT price, explain_obj FROM log_randombox_table WHERE user_pk=${decode?.pk} AND type=10`, type: 'list' },
            { table: "withdraw", sql: `SELECT price, explain_obj FROM log_star_table WHERE user_pk=${decode?.pk} AND type=4`, type: 'list' },
            { table: "purchase", sql: `SELECT SUM(price) AS purchase FROM log_star_table WHERE user_pk=${decode?.pk} AND (type=0 OR type=1)`, type: 'obj' },
        ];

        for (var i = 0; i < sql_list.length; i++) {
            result_list.push(queryPromise(sql_list[i].table, sql_list[i].sql, sql_list[i].type));
        }
        for (var i = 0; i < result_list.length; i++) {
            await result_list[i];
        }
        let result = (await when(result_list));
        for (var i = 0; i < (await result).length; i++) {
            obj[(await result[i])?.table] = (await result[i])?.data;
        }
        return response(req, res, 100, "success", obj)
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


const makeHash = (pw_) => {

    return new Promise(async (resolve, reject) => {
        let pw = pw_;
        if (!(typeof pw == 'string')) {
            pw = pw.toString();
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
const getGenealogyReturn = async (decode_) => {//유저기준 트리 가져오기
    let decode = decode_;
    if (decode?.pk) {
        let result = await dbQueryList(`SELECT pk, id, name, tier, depth, parent_pk FROM user_table`);
        result = result?.result;
        let list = [...result];
        let pk_idx_obj = {};
        for (var i = 0; i < list.length; i++) {
            pk_idx_obj[list[i].pk] = i;
        }
        let depth_list = [];
        for (var i = 0; i < max_child_depth(); i++) {
            depth_list[i] = {};
        }
        let auth = await dbQueryList(`SELECT pk, id, name, tier, depth, parent_pk FROM user_table WHERE pk=${decode?.pk}`);
        auth = auth?.result[0]
        depth_list[auth?.depth + 1][`${auth?.pk}`] = [];
        list = list.sort(function (a, b) {
            return a.depth - b.depth;
        })
        for (var i = 0; i < list.length; i++) {
            if (depth_list[list[i]?.depth][list[i]?.parent_pk] && list[i]?.depth) {
                depth_list[list[i]?.depth][list[i]?.parent_pk].push(list[i]);
                depth_list[list[i]?.depth + 1][`${list[i]?.pk}`] = [];
            }
        }
        depth_list[auth?.depth][`${auth?.parent_pk}`] = [{ ...auth }];
        return depth_list;
    } else {
        return [];
    }
}

const getParentUserList = async (decode_) => {//자신위의 유저들
    let decode = decode_;
    if (decode?.pk) {
        let user_tree = await getGenealogyReturn({ pk: 1 });
        let user_list = await dbQueryList('SELECT * FROM user_table');
        user_list = user_list?.result;
        let user_obj = {};
        for (var i = 0; i < user_list.length; i++) {
            user_obj[user_list[i]?.pk] = user_list[i];
        }
        let parent_list = [];
        let parent_pk = decode?.parent_pk;
        while (1) {
            let parent_user = user_obj[parent_pk];
            let direct_users = user_tree[parent_user?.depth + 1][parent_user?.pk];
            let pay_user_count = 0;
            for (var i = 0; i < direct_users.length; i++) {
                if (direct_users[i]?.tier / 5 > 0) {
                    pay_user_count++;
                }
            }
            parent_user['pay_user_count'] = pay_user_count;
            parent_list.push(parent_user);
            if (user_obj[parent_user?.parent_pk]?.user_level != 0) {
                break;
            } else {
                parent_pk = parent_user?.parent_pk;
            }
        }
        return parent_list;
    } else {
        return [];
    }
}
const getGenealogyScoreByGenealogyList = async (list_, decode_) => {//대실적, 소실적 구하기
    let get_score_by_tier = { 0: 0, 5: 36, 10: 120, 15: 360, 20: 600, 25: 1200 };
    let marketing_list = await dbQueryList(`SELECT * FROM log_randombox_table WHERE type=10`);
    marketing_list = marketing_list?.result;
    let list = [...list_];
    //console.log(JSON.stringify(list))
    let decode = { ...decode_ };
    let genealogy_score_list = [];
    for (var i = 0; i < list[decode?.depth + 1][decode?.pk].length; i++) {
        let score_list = await getGenealogyReturn(list[decode?.depth + 1][decode?.pk][i]);
        let score = 0;
        for (var j = 0; j < max_child_depth(); j++) {
            for (var k = 0; k < Object.keys(score_list[j]).length; k++) {
                //console.log(score_list[j][Object.keys(score_list[j])[k]]);
                let marketing_user_list = await marketing_list.map((item) => {
                    if (score_list[j][Object.keys(score_list[j])[k]].map((itm) => { return itm?.pk }).includes(item?.user_pk)) {
                        //console.log(JSON?.parse(item?.explain_obj)?.tier??0)
                        score += get_score_by_tier[JSON?.parse(item?.explain_obj)?.tier ?? 0]
                    } else {

                    }
                })
                //console.log(score_list[j][Object.keys(score_list[j])[k]].map((item)=>{return item?.pk}));
                //score += score_list[j][Object.keys(score_list[j])[k]].reduce((a, b) => a + (get_score_by_tier[b['tier']] || 0), 0);
            }
        }
        await genealogy_score_list.push(score);
    }
    let great = 0;
    let loss = 0;
    great = Math.max.apply(null, genealogy_score_list);
    loss = genealogy_score_list.reduce(function add(sum, currValue) {
        return sum + currValue;
    }, 0) - great;
    if (isNaN(parseInt(great))) {
        great = 0;
    }
    if (isNaN(parseInt(loss))) {
        loss = 0
    }
    return {
        great: great,//대실적점수
        loss: loss//소실적점수
    }
}
const getGenealogy = (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        let pk = decode.pk;
        db.query("SELECT pk, id, name, tier, depth, parent_pk, prider FROM user_table", async (err, result) => {
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
                for (var i = 0; i < max_child_depth(); i++) {
                    depth_list[i] = {};
                }
                let auth = await dbQueryList(`SELECT pk, id, name, tier, depth, parent_pk, prider FROM user_table WHERE pk=${decode?.pk}`)
                auth = auth?.result[0]
                if (decode.user_level < 40) {//유저가 불러올 때
                    depth_list[auth?.depth + 1][`${auth?.pk}`] = [];
                    list = list.sort(function (a, b) {
                        return a.depth - b.depth;
                    })
                    for (var i = 0; i < list.length; i++) {
                        if (depth_list[list[i]?.depth][list[i]?.parent_pk] && list[i]?.depth) {
                            depth_list[list[i]?.depth][list[i]?.parent_pk].push(list[i]);
                            depth_list[list[i]?.depth + 1][`${list[i]?.pk}`] = [];
                        }
                    }
                    depth_list[auth?.depth][`${auth?.parent_pk}`] = [{ ...auth }];
                } else {//관리자가 불러올 때
                    for (var i = 0; i < list.length; i++) {
                        if (!depth_list[list[i]?.depth][`${list[i]?.parent_pk}`]) {
                            depth_list[list[i]?.depth][`${list[i]?.parent_pk}`] = [];
                        }
                        depth_list[list[i]?.depth][`${list[i]?.parent_pk}`].push(list[i]);
                        depth_list[list[i]?.depth + 1][`${list[i]?.pk}`] = [];
                    }
                }
                return response(req, res, 100, "success", { data: depth_list, mine: auth });
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
        let result_list = [];
        let obj = {};
        let sql_list = [
            // {table:"randombox",sql:""},
            //  {table:"star",sql:""},
            // {table:"point",sql:""},
            { table: "user", sql: `SELECT id, parent_pk, parent_id, name, nickname, profile_img, tier FROM user_table WHERE pk=${decode?.pk}`, type: 'obj' },
            { table: "notice", sql: "SELECT * FROM notice_table WHERE status=1 ORDER BY sort DESC LIMIT 0, 3", type: 'list' },
            { table: "randombox", sql: `SELECT SUM(price) AS randombox FROM log_randombox_table WHERE user_pk=${decode.pk}`, type: 'obj' },
            { table: "star", sql: `SELECT SUM(price) AS star FROM log_star_table WHERE user_pk=${decode.pk}`, type: 'obj' },
            { table: "esgw", sql: `SELECT SUM(price) AS esgw FROM log_esgw_table WHERE user_pk=${decode.pk}`, type: 'obj' },
            { table: "point", sql: `SELECT SUM(price) AS point FROM log_point_table WHERE user_pk=${decode.pk}`, type: 'obj' },
            { table: "generation_star", sql: `SELECT SUM(price) AS generation_star FROM log_star_table WHERE user_pk=${decode.pk} AND type IN (7, 10, 14, 15) `, type: 'obj' },//선물받은것
            { table: "purchase_package", sql: ` SELECT * FROM log_randombox_table WHERE type=10 AND user_pk=${decode?.pk} `, type: 'list' },//선물받은것
            { table: "generation_point", sql: `SELECT SUM(price) AS generation_point FROM log_point_table WHERE user_pk=${decode.pk} AND type IN (7, 10, 14, 15) `, type: 'obj' },//선물받은것, 
            { table: "main_banner", sql: `SELECT * FROM main_banner_table WHERE status=1 ORDER BY sort DESC`, type: 'list' },//선물받은것, 
            { table: "sell_outlet", sql: `SELECT COUNT(*) AS sell_outlet FROM log_star_table WHERE user_pk=${decode?.pk} AND type=0 AND SUBSTR(date, 1, 7)='${returnMoment().substring(0, 7)}'`, type: 'obj' },//아울렛 구매이력, 
        ];
        let genealogy_list = await getGenealogyReturn(decode);
        let genealogy_score = await getGenealogyScoreByGenealogyList(genealogy_list, decode);
        obj['genealogy_score'] = genealogy_score;
        for (var i = 0; i < sql_list.length; i++) {
            result_list.push(queryPromise(sql_list[i].table, sql_list[i].sql, sql_list[i].type));
        }
        for (var i = 0; i < result_list.length; i++) {
            await result_list[i];
        }
        let result = (await when(result_list));
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
        console.log(sql)
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
        console.log(sql)
        console.log(values)
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
        if (table == 'outlet') {
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
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }

}
const getPartnerScoreByUserList = (req, res) => {
    try {
        let { list } = req.body;

    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const returnListBySchema = async (list_, schema_) => {
    let list = [...list_];
    let schema = schema_ ?? "";
    if (schema == 'user') {
        for (var i = 0; i < list.length; i++) {
            let genealogy_list = await getGenealogyReturn(list[i]);
            let genealogy_score = await getGenealogyScoreByGenealogyList(genealogy_list, list[i]);
            list[i]['partner'] = `${commarNumber(genealogy_score?.loss)} / ${commarNumber(genealogy_score?.great)}`;
        }
    }
    return list;
}
const getItems = (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        let { table, level, category_pk, brand_pk, status, user_pk, keyword, limit, page, page_cut, order, increase, is_popup, prider, tier, not_prider } = (req.query.table ? { ...req.query } : undefined) || (req.body.table ? { ...req.body } : undefined);
        let keyword_columns = getKewordListBySchema(table);
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
        if (is_popup) {
            whereStr += ` AND is_popup=${is_popup} `;
        }
        if (user_pk) {
            whereStr += ` AND user_pk=${user_pk} `;
        }
        if (increase) {
            whereStr += ` AND price${increase == 1 ? ' > 0 ' : ' < 0'} `;
        }
        if (prider) {
            whereStr += ` AND prider=${prider} `;
        }
        if (not_prider) {
            whereStr += ` AND prider!=${not_prider} `;
        }
        if (tier) {
            whereStr += ` AND tier=${tier} `;
        }
        if (table == 'user') {
            sql = "SELECT * "
            let money_categories = ['star', 'point', 'randombox', 'esgw'];
            for (var i = 0; i < money_categories.length; i++) {
                sql += `, (SELECT SUM(price) FROM log_${money_categories[i]}_table WHERE user_pk=user_table.pk) AS ${money_categories[i]} `
            }
            sql += ' FROM user_table '
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
        if (table == 'outlet_order') {
            pageSql = "SELECT COUNT(*) from ";
            pageSql += " log_star_table LEFT JOIN user_table ON log_star_table.user_pk=user_table.pk ";
            sql = "SELECT log_star_table.*, user_table.id AS user_id, user_table.name AS user_name, outlet_table.name AS item_name, outlet_table.sell_star AS item_price, outlet_table.sell_user_id, outlet_table.sell_user_name, outlet_table.sell_user_phone, outlet_table.sell_revenue_percent  from ";
            sql += " log_star_table LEFT JOIN user_table ON log_star_table.user_pk=user_table.pk ";
            sql += " LEFT JOIN outlet_table ON log_star_table.item_pk=outlet_table.pk ";
            whereStr += `AND log_star_table.type=0 `;
            if (decode?.user_level < 40) {
                whereStr += `AND user_pk=${decode?.pk} AND log_star_table.price < 0 `;
            } else {
                whereStr += `AND log_star_table.price < 0 `;
            }
        }
        if (table == 'log_manager_action') {
            pageSql = 'SELECT COUNT(*) FROM log_manager_action_table ';
            pageSql += " log_manager_action_table LEFT JOIN user_table ON log_manager_action_table.user_pk=user_table.pk ";
            sql = "SELECT log_manager_action_table.*, user_table.id AS user_id, user_table.name AS user_name FROM ";
            sql += " log_manager_action_table LEFT JOIN user_table ON log_manager_action_table.user_pk=user_table.pk ";
        }
        if (table == 'log_star' || table == 'log_point' || table == 'log_randombox' || table == 'log_esgw') {
            pageSql += ` ${table}_table LEFT JOIN user_table ON ${table}_table.user_pk=user_table.pk`;
            sql = `SELECT ${table}_table.*, user_table.id AS user_id, user_table.name AS user_name FROM `;
            sql += ` ${table}_table LEFT JOIN user_table ON ${table}_table.user_pk=user_table.pk`;
            if (decode.user_level < 40) {
                whereStr += `AND user_pk=${decode.pk}`;
            }
        }
        if (table == 'log_subscriptiondeposit') {
            pageSql += ` ${table}_table LEFT JOIN user_table ON ${table}_table.user_pk=user_table.pk`;
            sql = `SELECT ${table}_table.*, user_table.id AS user_id, user_table.name AS user_name FROM `;
            sql += ` ${table}_table LEFT JOIN user_table ON ${table}_table.user_pk=user_table.pk`;
            if (decode.user_level < 40) {
                whereStr += `AND user_pk=${decode.pk}`;
            } else {
                whereStr += ' AND type=8 '
            }
        }
        if (table == 'exchange') {
            pageSql = 'SELECT COUNT(*) FROM log_star_table ';
            pageSql += " log_star_table LEFT JOIN user_table u_u ON log_star_table.user_pk=u_u.pk ";
            sql = "SELECT log_star_table.*, u_u.id AS user_id, u_u.name AS user_name, u_u.bank_name, u_u.account_number, u_u.account_name, m_u.id AS manager_id, m_u.name AS manager_name FROM ";
            sql += " log_star_table LEFT JOIN user_table u_u ON log_star_table.user_pk=u_u.pk ";
            sql += "  LEFT JOIN user_table m_u ON log_star_table.manager_pk=m_u.pk ";
            whereStr += ` AND log_star_table.type=4 `;
            if (decode.user_level < 40) {
                whereStr += `AND u_u.pk=${decode.pk}`;
            } else {
                whereStr += `AND log_star_table.price < 0 `;
            }
        }
        if (table == 'log_withdraw') {
            sql = "SELECT log_star_table.*, user_table.id AS user_id, user_table.name AS user_name FROM ";
            sql += " log_star_table LEFT JOIN user_table ON log_star_table.user_pk=user_table.pk ";
            whereStr += ` AND log_star_table.type=4 `;
        }
        if (table == 'marketing') {
            pageSql = 'SELECT COUNT(*) FROM log_randombox_table ';
            pageSql += " log_randombox_table LEFT JOIN user_table u_u ON log_randombox_table.user_pk=u_u.pk ";
            sql = "SELECT log_randombox_table.*, u_u.id AS user_id, u_u.name AS user_name, m_u.id AS manager_id, m_u.name AS manager_name  FROM ";
            sql += " log_randombox_table LEFT JOIN user_table u_u ON log_randombox_table.user_pk=u_u.pk ";
            sql += "  LEFT JOIN user_table m_u ON log_randombox_table.manager_pk=m_u.pk ";
            whereStr += ` AND log_randombox_table.type=10 `;
        }
        if (table == 'user_subscriptiondeposit') {
            pageSql = `SELECT COUNT(*) FROM user_table `;
            sql = "SELECT * "
            let money_categories = ['star', 'point', 'randombox', 'esgw'];
            for (var i = 0; i < money_categories.length; i++) {
                sql += `, (SELECT SUM(price) FROM log_${money_categories[i]}_table WHERE user_pk=user_table.pk AND type=8) AS ${money_categories[i]} `
            }
            sql += ' FROM user_table '
        }
        if (keyword) {
            if (keyword_columns?.length > 0) {
                whereStr += " AND (";
                for (var i = 0; i < keyword_columns.length; i++) {
                    whereStr += ` ${i != 0 ? 'OR' : ''} ${keyword_columns[i]} LIKE '%${keyword}%' `;
                }
                whereStr += ")";
            }
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
                    await db.query(sql, async (err, result2) => {
                        if (err) {
                            console.log(err)
                            return response(req, res, -200, "서버 에러 발생", [])
                        } else {
                            let maxPage = result1[0]['COUNT(*)'] % page_cut == 0 ? (result1[0]['COUNT(*)'] / page_cut) : ((result1[0]['COUNT(*)'] - result1[0]['COUNT(*)'] % page_cut) / page_cut + 1);
                            let data = await returnListBySchema(result2, table);
                            return response(req, res, 100, "success", { data: data, maxPage: maxPage });
                        }
                    })
                }
            })
        } else {
            db.query(sql, async (err, result) => {
                if (err) {
                    console.log(err)
                    return response(req, res, -200, "서버 에러 발생", [])
                } else {
                    let data = await returnListBySchema(result, table);
                    return response(req, res, 100, "success", data)
                }
            })
        }
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getSubscriptionDepositHistory = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", []);
        }
        let { page_cut, page } = req.body;
        if (!page_cut) {
            page_cut = page_cut;
        }
        if (!page) {
            page = 1;
        }
        let result_list = [];
        let obj = {};
        let sql_list = [
            // {table:"randombox",sql:""},
            //  {table:"star",sql:""},
            // {table:"point",sql:""},
            { table: "star", sql: `SELECT log_star_table.*, '스타' AS category, user_table.id AS user_id, user_table.name AS user_name FROM log_star_table LEFT JOIN user_table ON log_star_table.user_pk=user_table.pk WHERE log_star_table.type=8 `, type: 'list' },
            { table: "point", sql: `SELECT log_point_table.*, '포인트' AS category, user_table.id AS user_id, user_table.name AS user_name FROM log_point_table LEFT JOIN user_table ON log_point_table.user_pk=user_table.pk WHERE log_point_table.type=8 `, type: 'list' },
            { table: "esgw", sql: `SELECT log_esgw_table.*, 'ESGWP' AS category, user_table.id AS user_id, user_table.name AS user_name FROM log_esgw_table LEFT JOIN user_table ON log_esgw_table.user_pk=user_table.pk WHERE log_esgw_table.type=8`, type: 'list' },
        ];

        for (var i = 0; i < sql_list.length; i++) {
            result_list.push(queryPromise(sql_list[i].table, sql_list[i].sql, sql_list[i].type));
        }
        for (var i = 0; i < result_list.length; i++) {
            await result_list[i];
        }
        let result = (await when(result_list));
        for (var i = 0; i < (await result).length; i++) {
            obj[(await result[i])?.table] = (await result[i])?.data ?? [];
        }
        let list = [...obj?.star, ...obj?.point, ...obj?.esgw];
        list = await list.sort(function (a, b) {
            let x = a.date.toLowerCase();
            let y = b.date.toLowerCase();
            if (x > y) {
                return -1;
            }
            if (x < y) {
                return 1;
            }
            return 0;
        });
        if (req.body.page) {
            let maxPage = makeMaxPage(list?.length, page_cut);
            let data = list.slice((page - 1) * page_cut, page * page_cut);
            return response(req, res, 100, "success", { maxPage: maxPage, data: data });
        } else {
            return response(req, res, 100, "success", list);
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
const getGiftHistory = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        let { page, page_cut } = req.query;
        let result_list = [];
        let obj = {};
        let sql_list = [
            // {table:"randombox",sql:""},
            //  {table:"star",sql:""},
            // {table:"point",sql:""},
            { table: "star", sql: "SELECT *, '스타' AS category  FROM log_star_table WHERE type=3 AND price < 0  ", type: 'list' },
            { table: "point", sql: "SELECT *, '포인트' AS category  FROM log_point_table WHERE type=3 AND price < 0 ", type: 'list' },
            { table: "esgw", sql: "SELECT *, 'ESGW 포인트' AS category  FROM log_esgw_table WHERE type=3 AND price < 0 ", type: 'list' },
        ];
        for (var i = 0; i < sql_list.length; i++) {
            result_list.push(queryPromise(sql_list[i].table, sql_list[i].sql, sql_list[i].type));
        }
        for (var i = 0; i < result_list.length; i++) {
            await result_list[i];
        }
        let result = (await when(result_list));
        let ans_list = [];
        for (var i = 0; i < (await result).length; i++) {
            ans_list = [...ans_list, ...(await result[i])?.data];
        }
        ans_list = await ans_list.sort(function (a, b) {
            let x = a.date.toLowerCase();
            let y = b.date.toLowerCase();
            if (x > y) {
                return -1;
            }
            if (x < y) {
                return 1;
            }
            return 0;
        });
        if (page) {
            let maxPage = makeMaxPage(ans_list.length, page_cut);
            ans_list = ans_list.slice((page - 1) * page_cut, page * page_cut);
            return response(req, res, 100, "success", { maxPage: maxPage, data: ans_list })
        } else {
            return response(req, res, 100, "success", ans_list)
        }
    } catch (err) {
        console.log(err)
        return response(req, res, -200, "서버 에러 발생", [])
    }
}
const getRandomboxRollingHistory = async (req, res) => {
    try {
        const decode = checkLevel(req.cookies.token, 0);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        }
        let { increase, page, page_cut } = req.query;
        let result_list = [];
        let obj = {};
        let sql_list = [
            // {table:"randombox",sql:""},
            //  {table:"star",sql:""},
            // {table:"point",sql:""},
            { table: "star", sql: `SELECT *, '스타' AS category  FROM log_star_table WHERE type=11 AND user_pk=${decode?.pk}`, type: 'list' },
            { table: "point", sql: `SELECT *, '포인트' AS category  FROM log_point_table WHERE type=11 AND user_pk=${decode?.pk} `, type: 'list' },
            { table: "randombox", sql: `SELECT *, '랜덤박스 포인트' AS category  FROM log_randombox_table WHERE type=11 AND user_pk=${decode?.pk} `, type: 'list' },
        ];
        for (var i = 0; i < sql_list.length; i++) {
            if (increase) {
                sql_list[i].sql += ` AND price${increase == 1 ? ' > 0 ' : ' < 0'} `
            }
            result_list.push(queryPromise(sql_list[i].table, sql_list[i].sql, sql_list[i].type));
        }
        for (var i = 0; i < result_list.length; i++) {
            await result_list[i];
        }
        let result = (await when(result_list));
        let ans_list = [];
        for (var i = 0; i < (await result).length; i++) {
            ans_list = [...ans_list, ...(await result[i])?.data];
        }
        ans_list = await ans_list.sort(function (a, b) {
            let x = a.date.toLowerCase();
            let y = b.date.toLowerCase();
            if (x > y) {
                return -1;
            }
            if (x < y) {
                return 1;
            }
            return 0;
        });
        if (page) {
            let maxPage = makeMaxPage(ans_list.length, page_cut);
            ans_list = ans_list.slice((page - 1) * page_cut, page * page_cut);
            return response(req, res, 100, "success", { maxPage: maxPage, data: ans_list })
        } else {
            return response(req, res, 100, "success", ans_list)
        }
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
        const decode = checkLevel(req.cookies.token, 40);
        if (!decode) {
            return response(req, res, -150, "권한이 없습니다.", [])
        } else {
            const { withdraw_commission_percent, withdraw_start_time, withdraw_end_time, withdraw_0, withdraw_5, withdraw_10, withdraw_15, withdraw_20, withdraw_25, withdraw_note, pk } = req.body;
            let sql = 'UPDATE setting_table SET withdraw_commission_percent=?, withdraw_start_time=?, withdraw_end_time=?, withdraw_0=?, withdraw_5=?, withdraw_10=?, withdraw_15=?, withdraw_20=?, withdraw_25=?, withdraw_note=?  WHERE pk=?';
            values = [withdraw_commission_percent, withdraw_start_time, withdraw_end_time, withdraw_0, withdraw_5, withdraw_10, withdraw_15, withdraw_20, withdraw_25, withdraw_note, pk];
            db.query(sql, values, (err, result) => {
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
            const { type_percent, money, money_percent, date, randombox_initialization_time, pk } = req.body;
            console.log(req.body)
            db.query('UPDATE daily_percentage_table SET type_percent=?, money=?, money_percent=?, date=?, randombox_initialization_time=?  WHERE pk=?', [type_percent, money, money_percent, date, randombox_initialization_time, pk], (err, result) => {
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
    getUsers, getItems, getItem, getHomeContent, getSetting, getVideo, findIdByPhone, findAuthByIdAndPhone, getComments, getCommentsManager, getDailyPercent, getAddressByText, getAllDataByTables, getGenealogy, getUserMoney, getGiftHistory, getRandomboxRollingHistory, getMyPageContent, getSubscriptionDepositHistory,//select
    addMaster, onSignUp, addItem, addNoteImage, addSetting, addComment, addAlarm,//insert 
    updateUser, updateItem, updateMaster, updateSetting, updateStatus, onTheTopItem, changeItemSequence, changePassword, updateComment, updateAlarm, updateDailyPercent, updateUserMoneyByManager, lotteryDailyPoint, onChangeExchangeStatus, onChangeOutletOrderStatus, initializationIdCard, updateUserSubscriptionDepositByManager,//update
    deleteItem,
    requestWithdraw, onGift, registerRandomBox, buyESGWPoint, subscriptionDeposit, onOutletOrder, addMarketing, addMonthSettle, getWeekSettleChild, onWeekSettle, insertUserMoneyByExcel
};