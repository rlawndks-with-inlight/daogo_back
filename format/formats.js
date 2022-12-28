const { insertQuery } = require('../query-util')

const insertUserMoneyLog = async (log_list_) => {
    let log_list = [...log_list_];
    if (log_list.length <= 0) {
        return;
    }
    let star_pk = 0;

    let is_exist_star = false;
    for (var i = 0; i < log_list.length; i++) {
        if (log_list[i]?.table == 'star') {
            is_exist_star = true;
        }
    }
    if (!is_exist_star) {
        log_list.unshift({
            table: 'star',
            price: 0,
            user_pk: log_list[0]?.user_pk,
            type: log_list[0]?.type,
            note: log_list[0]?.note,
        })
    }
    for(var i = 0;i<log_list.length;i++){
        if (log_list[i]?.table == 'star') {
            let tmp = log_list[i];
            log_list[i] = log_list[0];
            log_list[0] = tmp;
            break;
        }
    }
    for (var i = 0; i < log_list.length; i++) {
        let insert_keys = ['price', 'user_pk', 'type', 'note', 'explain_obj', 'manager_pk', 'item_pk'];
        let insert_values = ['?', '?', '?', '?', '?', '?', '?'];
        let insert_list = [log_list[i]?.price, log_list[i]?.user_pk, log_list[i]?.type, log_list[i]?.note ?? "", log_list[i]?.explain_obj ?? "{}", log_list[i]?.manager_pk ?? 0, log_list[i]?.item_pk ?? 0];
        if (log_list[i]?.table != 'star') {
            insert_list.push(star_pk);
            insert_keys.push('star_pk');
            insert_values.push('?');
        }
        let result = await insertQuery(`INSERT INTO log_${log_list[i]?.table}_table (${insert_keys.join()}) VALUES (${insert_values.join()})`, insert_list);
        if (log_list[i]?.table == 'star') {
            star_pk = result?.result?.insertId;
        }
    }
}
const insertUserMoneyLogObjFormat = (table, price, user_pk, type, explain_obj, note, manager_pk) => {
    return {
        table: table,
        price: price,
        user_pk: user_pk,
        type: type,
        explain_obj: explain_obj,
        note: note,
        manager_pk: manager_pk
    }
}
module.exports = {
    insertUserMoneyLog, insertUserMoneyLogObjFormat
}