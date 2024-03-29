const express = require('express');
const router = express.Router();
const { upload } = require('../config/multerConfig');
const {
    onLoginById, getUserToken, onLogout, checkExistId, checkExistNickname, sendSms, kakaoCallBack, editMyInfo, uploadProfile,//auth
    getUsers, getItems, getItem, getHomeContent, getSetting, getVideo, findIdByPhone, findAuthByIdAndPhone, getComments, getCommentsManager, getDailyPercent, getAddressByText, getAllDataByTables, getGenealogy, getUserMoney, getGiftHistory, getRandomboxRollingHistory, getMyPageContent, getSubscriptionDepositHistory,//select
    addMaster, onSignUp, addItem, addNoteImage, addSetting, addComment, addAlarm,//insert 
    updateUser, updateItem, updateMaster, updateSetting, updateStatus, onTheTopItem, changeItemSequence, changePassword, updateComment, updateAlarm, updateDailyPercent, updateUserMoneyByManager, lotteryDailyPoint, onChangeExchangeStatus, onChangeOutletOrderStatus, initializationIdCard, updateUserSubscriptionDepositByManager,//update
    deleteItem,
    requestWithdraw, onGift, onAuctionParticipate, getParticipateUsers, onAuctionDeadline, getMyAuctionCheckList,getAllAuctionCheckList, registerRandomBox, buyESGWPoint, subscriptionDeposit, onOutletOrder, addMarketing, addMonthSettle, getWeekSettleChild, onWeekSettle, insertUserMoneyByExcel, getExchangeHistory, onChangeExchangeBatch
} = require('./api')

router.post('/addalarm', addAlarm);
router.post('/updatealarm', updateAlarm);
router.post('/uploadprofile', upload.single('profile'), uploadProfile)
router.post('/kakao/callback', kakaoCallBack);
router.post('/sendsms', sendSms);
router.post('/findidbyphone', findIdByPhone);
router.post('/findauthbyidandphone', findAuthByIdAndPhone);
router.post('/checkexistid', checkExistId);
router.post('/checkexistnickname', checkExistNickname);
router.post('/changepassword', changePassword);
router.post('/adduser', onSignUp);
router.post('/addmaster', upload.fields([{ name: 'master' }, { name: 'channel' }]), addMaster);
router.post('/updatemaster', upload.fields([{ name: 'master' }, { name: 'channel' }]), updateMaster);
//router.post('/addchannel', upload.single('channel'), addChannel);
//router.post('/updatechannel', upload.single('channel'), updateChannel);
//router.get('/getchannel', getChannelList);
router.post('/loginbyid', onLoginById);
//router.post('/loginbysns', onLoginBySns);
router.post('/logout', onLogout);
router.get('/users', getUsers);
//router.post('/addoneword', upload.single('content'), addOneWord);
//router.post('/addoneevent', upload.single('content'), addOneEvent);
router.post('/editmyinfo', upload.fields([{ name: 'profile' }]), editMyInfo);
router.get('/auth', getUserToken);
router.post('/additem', upload.fields([{ name: 'banner' }, { name: 'coupon' }, { name: 'outlet' }, { name: 'auction' }]), addItem);
router.post('/updateitem', upload.fields([{ name: 'banner' }, { name: 'coupon' }, { name: 'outlet' }, { name: 'auction' }]), updateItem);
router.post('/deleteitem', deleteItem);
router.post('/getalldatabytables', getAllDataByTables);
router.post('/getgenealogy', getGenealogy);
router.get('/getusermoney', getUserMoney);
router.post('/updateuser', upload.single('profile'), updateUser);
router.get('/getdailypercent', getDailyPercent);
router.post('/updatedailypercent', updateDailyPercent);
router.get('/getsetting', getSetting);
router.post('/updateusermoneybymanager', updateUserMoneyByManager);
router.post('/updateusersubscriptiondepositbymanager', updateUserSubscriptionDepositByManager);
router.post('/lotterydailypoint', lotteryDailyPoint);
router.post('/registerrandomBox', registerRandomBox);
router.post('/ongift', onGift);
router.post('/getparticipateusers', getParticipateUsers);
router.post('/onauctionparticipate', onAuctionParticipate);
router.post('/onauctiondeadline', onAuctionDeadline);
router.post('/getmyauctionchecklist', getMyAuctionCheckList);
router.post('/getallauctionchecklist', getAllAuctionCheckList);
router.post('/requestWithdraw', requestWithdraw);
router.post('/buyesgwpoint', buyESGWPoint);
router.post('/subscriptiondeposit', subscriptionDeposit);
router.post('/onoutletorder', onOutletOrder);
router.post('/addmarketing', addMarketing);
router.post('/addmonthsettle', addMonthSettle);
router.get('/gifthistory', getGiftHistory);
router.get('/randomboxrollinghistory', getRandomboxRollingHistory);
router.get('/exchangehistory', getExchangeHistory);
router.post('/onchangeexchangestatus', onChangeExchangeStatus);
router.post('/onchangeexchangebatch', onChangeExchangeBatch);
router.post('/onchangeoutletorderstatus', onChangeOutletOrderStatus);
router.post('/initializationidcard', initializationIdCard);
router.get('/getweeksettlechild', getWeekSettleChild);
router.post('/onweeksettle', onWeekSettle);
router.post('/insertusermoneybyexcel', insertUserMoneyByExcel);
//router.post('/addvideo', addVideo);
//router.post('/updatevideo', updateVideo);
//router.post('/addnotice', addNotice);
//router.post('/updatenotice', updateNotice);
//router.post('/addissuecategory', upload.single('content'), addIssueCategory);
//router.post('/updateissuecategory', upload.single('content'), updateIssueCategory);
//router.post('/addfeaturecategory', upload.single('content'), addFeatureCategory);
//router.post('/updatefeaturecategory', upload.single('content'), updateFeatureCategory);
router.post('/addimage', upload.single('note'), addNoteImage);
//router.post('/resign', onResign);
//router.get('/oneword', getOneWord);
//router.get('/oneevent', getOneEvent);
router.get('/items', getItems);
router.post('/items', getItems);
router.post('/getsubscriptiondeposithistory', getSubscriptionDepositHistory);
router.get('/item', getItem);
router.get('/gethomecontent', getHomeContent);
router.get('/getmypagecontent', getMyPageContent);
router.post('/getmypagecontent', getMyPageContent);
router.post('/updatesetting', updateSetting);
router.post('/addsetting', upload.single('master'), addSetting);
router.post('/updatestatus', updateStatus);
//router.get('/getvideocontent', getVideoContent);
router.get('/video/:pk', getVideo);
router.post('/onthetopitem', onTheTopItem);
router.post('/changeitemsequence', changeItemSequence);
router.get('/getcommnets', getComments);
router.post('/addcomment', addComment); getCommentsManager
router.post('/updatecomment', updateComment);
router.get('/getcommentsmanager', getCommentsManager);
//router.post('/getcountnotreadnoti', getCountNotReadNoti);
//router.get('/getnoticeandalarmlastpk', getNoticeAndAlarmLastPk);
router.post('/getaddressbytext', getAddressByText);

module.exports = router;