---
title: "AsusOptimization.exe"
dateString: June 2025
draft: false
tags: ["Asus"]
weight: 30
date: 2025-06-29
categories: ["ETC"]
---

어제 노트북 덮개 닫고 hdmi 연결해서 CTF 뛰고 있었는데, 혼자서 노트북이 꺼졌다.

![](/blog/AsusOptimizer/angry_seohyeon.jpg)

전에도 자기 혼자서 꺼졌었는데, CTF 하다가 꺼진건 처음이라 화나서 로그를 뒤지기 시작했다.

![](/blog/AsusOptimizer/image.png)

보면 갑자기 12시 45분에 뜬금없이 Standby로 진입한다.

![](/blog/AsusOptimizer/image-1.png)
![](/blog/AsusOptimizer/image-2.png)

뭔가 어떤 유저 프로세스가 분탕을 치고 있는게 확실하다.

![](/blog/AsusOptimizer/image-3.png)

![](/blog/AsusOptimizer/image-4.png)

`sub_1400056D0` 에서 108, 109 case의 `call_0_0_0` 이라고 네이밍 해놓은게 sleep 로직이다.

![](/blog/AsusOptimizer/image-5.png)
![](/blog/AsusOptimizer/image-6.png)

이렇게 가지치기 해주고, 이 새로운 optimizer.exe로 기존거를 덮어씌워줬다.
대충 잘 동작하는거 같다.
[optimizer.exe](/blog/AsusOptimizer/AsusOptimization.7z)