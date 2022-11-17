const express = require('express');
const router = express.Router();
const { upload } = require('../config/multerConfig')
const {
    onLoginById, getUserToken, onLogout, checkExistId, checkExistNickname, sendSms, kakaoCallBack, editMyInfo, uploadProfile, onLoginBySns,//auth
    getUsers, getOneWord, getOneEvent, getItems, getItem, getHomeContent, getSetting, getVideoContent, getChannelList, getVideo, onSearchAllItem, findIdByPhone, findAuthByIdAndPhone, getComments, getCommentsManager, getCountNotReadNoti, getNoticeAndAlarmLastPk, getDailyPercent,//select
    addMaster, onSignUp, addOneWord, addOneEvent, addItem, addIssueCategory, addNoteImage, addVideo, addSetting, addChannel, addFeatureCategory, addNotice, addComment, addAlarm,//insert 
    updateUser, updateItem, updateIssueCategory, updateVideo, updateMaster, updateSetting, updateStatus, updateChannel, updateFeatureCategory, updateNotice, onTheTopItem, changeItemSequence, changePassword, updateComment, updateAlarm, updateDailyPercent,//update
    deleteItem, onResign,
} = require('./api')
router.get('/getdailypercent',getDailyPercent);
router.post('/updatedailypercent',updateDailyPercent);
router.post('/addalarm', addAlarm);
router.post('/updatealarm', updateAlarm);
router.post('/editmyinfo', editMyInfo);
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
router.post('/addchannel', upload.single('channel'), addChannel);
router.post('/updatechannel', upload.single('channel'), updateChannel);
router.get('/getchannel', getChannelList);
router.post('/loginbyid', onLoginById);
router.post('/loginbysns', onLoginBySns);
router.post('/logout', onLogout);
router.get('/auth', getUserToken);
router.get('/users', getUsers);
router.post('/addoneword', upload.single('content'), addOneWord);
router.post('/addoneevent', upload.single('content'), addOneEvent);
router.post('/additem', upload.fields([{ name: 'content' }, { name: 'content2' }]), addItem);
router.post('/updateitem', upload.fields([{ name: 'content' }, { name: 'content2' }]), updateItem);
router.post('/addvideo', addVideo);
router.post('/updatevideo', updateVideo);
router.post('/addnotice', addNotice);
router.post('/updatenotice', updateNotice);
router.post('/addissuecategory', upload.single('content'), addIssueCategory);
router.post('/updateissuecategory', upload.single('content'), updateIssueCategory);
router.post('/addfeaturecategory', upload.single('content'), addFeatureCategory);
router.post('/updatefeaturecategory', upload.single('content'), updateFeatureCategory);
router.post('/addimage', upload.single('note'), addNoteImage);
router.post('/deleteitem', deleteItem);
router.post('/resign', onResign);
router.post('/updateuser', updateUser);
router.get('/onsearchallitem', onSearchAllItem);
router.get('/oneword', getOneWord);
router.get('/oneevent', getOneEvent);
router.get('/items', getItems);
router.get('/item', getItem);
router.get('/gethomecontent', getHomeContent);
router.post('/updatesetting', upload.single('master'), updateSetting);
router.post('/addsetting', upload.single('master'), addSetting);
router.get('/setting', getSetting);
router.post('/updatestatus', updateStatus);
router.get('/getvideocontent', getVideoContent);
router.get('/video/:pk', getVideo);
router.post('/onthetopitem', onTheTopItem);
router.post('/changeitemsequence', changeItemSequence);
router.get('/getcommnets', getComments);
router.post('/addcomment', addComment); getCommentsManager
router.post('/updatecomment', updateComment);
router.get('/getcommentsmanager', getCommentsManager);
router.post('/getcountnotreadnoti', getCountNotReadNoti);
router.get('/getnoticeandalarmlastpk', getNoticeAndAlarmLastPk);

module.exports = router;