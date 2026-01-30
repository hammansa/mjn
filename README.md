# Maejinnam (매진남)

간단한 Flask 앱입니다. 로컬 실행 및 테스트 방법:

1) 가상환경 활성화

Windows PowerShell:

```powershell
& .\.venv\Scripts\Activate.ps1
```

2) 의존성 설치

```powershell
python -m pip install -r requirements.txt
```

3) (선택) ORM 사용 시 환경변수 설정

```powershell
$env:USE_SQLALCHEMY='1'
$env:DATABASE_URL='sqlite:///maejinnam.db'
```

4) 앱 실행

```powershell
python app.py
```

5) 테스트 실행

```powershell
python -m pytest -q
```

환경변수:
- `MAEJINNAM_SECRET` : 앱 시크릿
- `USE_SQLALCHEMY` : '1'로 설정 시 SQLAlchemy 사용
- `DATABASE_URL` : SQLAlchemy 사용 시 DB URL
- `DATABASE_FILE` : sqlite 파일 경로(기본: maejinnam.db)
- `MAEJINNAM_CSP`, `MAEJINNAM_CSP_DEBUG` : CSP 문자열을 완전히 외부화

문의: 추가 마이그레이션(Alembic), 테스트 커버리지 확대, CSP 세부 구성 지원 가능합니다.
