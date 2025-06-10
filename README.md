
<h1 align="center">🔧javame-gateway🔧</h1>
<div align="center">
Front에서 오는 모든 요청을 받는 gateway입니다.
</br></br>
사용자가 특정 회사도메인(ex. javame.com, nhnacamey.com)으로 요청을 보내지 않고 companyDomain으로만 요청을 하게되면
</br>
gateway에서 companyDomain -> javame.com으로 변경을 하여 보안성을 높였습니다.
</br></br>
라우터 기능을 가지고 있어서 /api/v1/memeber로 URI로 전송시 Javame-member-api로 응답을 보내주는 기능을 하고있습니다.
</br></br>
또한, Front에서 요청을 보내게 되면 header에 JWT Token을 추가하여 전송하게 되는데
</br>
gateway에서 email, role로 변경하여 다시 header에 넣어 backend의 service or api로 전송하여 사용할수 있게 합니다.
</div>

</br>
</br>
<div align="center">
<h3 tabindex="-1" class="heading-element" dir="auto">사용스택</h3>



  
![Java](https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=openjdk&logoColor=white)
![MySQL](https://img.shields.io/badge/mysql-4479A1.svg?style=for-the-badge&logo=mysql&logoColor=white)
![Spring](https://img.shields.io/badge/spring-%236DB33F.svg?style=for-the-badge&logo=spring&logoColor=white)
<img src="https://img.shields.io/badge/springboot-6DB33F?style=for-the-badge&logo=springboot&logoColor=white">

![GitHub](https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)</br>
<img src="https://img.shields.io/badge/JUnit5-25A162?style=for-the-badge&logo=JUnit5&logoColor=white">
![SonarQube](https://img.shields.io/badge/SonarQube-black?style=for-the-badge&logo=sonarqube&logoColor=4E9BCD)
</br>
</br>
</div>
</br>
</br>
</br>

<div align=center>
<h3 tabindex="-1" class="heading-element" dir="auto">서비스 아키텍쳐</h3> 
  
이미지 추가하기ㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣ

</br>
<h3 tabindex="-1" class="heading-element" dir="auto">사용자 → Gateway → Backend</h3> 
</div>

</br>
</br>

<div align=center>
<h3 tabindex="-1" class="heading-element" dir="auto">Test Coverage (Targe:Line coverage 80%)</h3> 
  <li>
    Line coverage: 93.9% (2025. 05. 15. 기준)
  </li>
  </br>

테스트 커버리지 이미지 추가하기 ㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣㅣ

</div>
