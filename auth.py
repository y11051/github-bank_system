import getpass
import hashlib
import random
import sys
from datetime import datetime, timedelta


def _msvcrt_read_password_hidden(prompt: str) -> str:
    """
    Windows 전용: 글자 단위 입력 시 화면에는 '*' 만 표시 (Cursor 등 비-TTY 환경에서도 동작).
    """
    import msvcrt

    sys.stdout.write(prompt)
    sys.stdout.flush()
    buf = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            sys.stdout.write("\n")
            sys.stdout.flush()
            break
        if ch == "\x08":  # Backspace
            if buf:
                buf.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
        elif ch == "\x03":  # Ctrl+C
            raise KeyboardInterrupt
        else:
            buf.append(ch)
            sys.stdout.write("*")
            sys.stdout.flush()
    return "".join(buf).strip()


def _read_password_hidden(prompt: str) -> str:
    """
    비밀번호 입력: 터미널에 평문이 찍히지 않도록 처리.
    - Windows: msvcrt 로 마스킹 (관리자/일반 동일하게 login·register 모두 적용)
    - 그 외: getpass (TTY 일 때 마스킹)
    - msvcrt 실패 시 getpass 로 폴백
    """
    if sys.platform == "win32":
        try:
            return _msvcrt_read_password_hidden(prompt)
        except Exception:
            pass
    try:
        return getpass.getpass(prompt).strip()
    except Exception:
        return ""


# ──────────────────────────────────────────────
# 공통 유틸 함수
# ──────────────────────────────────────────────

def hash_password(password):
    """비밀번호를 SHA256으로 해싱합니다."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_auth_code():
    """6자리 보안 인증 코드를 생성합니다."""
    return str(random.randint(100000, 999999))

def verify_auth_time(expire_at):
    """인증 제한 시간(3분)을 검증합니다. 만료 전이면 True 반환."""
    if datetime.now() > expire_at:
        return False
    return True

# ──────────────────────────────────────────────
# 회원가입 (F-01)
# ──────────────────────────────────────────────

def register(conn):
    """
    신규 회원 등록.
    - 문자열 상수(ROLE, IS_DELETED)는 바인드로 전달 (ORA-01745 방지)
    - SEQ_USER_ID.NEXTVAL, SYSDATE는 SQL에 직접 기술
    """
    print("\n[ 회원가입 ]")
    username = input("  이름을 입력하세요: ").strip()
    # USERS.NAME 은 VARCHAR2(30) NOT NULL — 길이·공백 검증 (전화번호 컬럼은 스키마에 없음)
    if not username:
        print("  ❌ 이름을 입력해 주세요.")
        return
    if len(username) > 30:
        print("  ❌ 이름은 최대 30자까지입니다(DB NOT NULL/VARCHAR2 제약).")
        return
    # 비밀번호는 터미널에 평문 출력되지 않도록 마스킹 입력
    password = _read_password_hidden("  비밀번호를 입력하세요: ")
    confirm  = _read_password_hidden("  비밀번호를 한 번 더 입력하세요: ")

    if not password:
        print("  ❌ 비밀번호를 입력해 주세요.")
        return
    if password != confirm:
        print("  ❌ 비밀번호가 일치하지 않습니다.")
        return

    pwd_hash = hash_password(password)

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO USERS (USER_ID, NAME, PWD_HASH, ROLE, IS_DELETED, CREATED_AT)
            VALUES (SEQ_USER_ID.NEXTVAL, :user_name, :pwd_hash, :role_code, :is_deleted, SYSDATE)
            """,
            {
                "user_name": username,
                "pwd_hash": pwd_hash,
                "role_code": "USER",
                "is_deleted": "N",
            }
        )
        conn.commit()
        print(f"  ✅ '{username}' 님, 회원가입이 완료되었습니다!")
    except Exception as e:
        conn.rollback()
        print(f"  ❌ 회원가입 실패 → {str(e)}")
    finally:
        cursor.close()

# ──────────────────────────────────────────────
# 로그인 (F-02)
# ──────────────────────────────────────────────

def login(conn):
    """
    로그인.
    - NAME 컬럼 비교값은 :user_name 바인드 (컬럼명 NAME과 혼동 없음)
    """
    print("\n[ 로그인 ]")
    username = input("  이름을 입력하세요: ").strip()
    password = _read_password_hidden("  비밀번호를 입력하세요: ")
    if not password:
        print("  ❌ 비밀번호를 입력해 주세요.")
        return None

    pwd_hash = hash_password(password)

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT USER_ID, NAME, ROLE
            FROM   USERS
            WHERE  NAME        = :user_name
              AND  PWD_HASH    = :pwd_hash
              AND  IS_DELETED  = :is_deleted
            """,
            {
                "user_name": username,
                "pwd_hash": pwd_hash,
                "is_deleted": "N",
            }
        )
        row = cursor.fetchone()

        if row:
            # 로그인 성공: 반드시 user_id, name, role 포함 (관리자/일반 분기용)
            role_raw = row[2] if row[2] is not None else "USER"
            role = str(role_raw).strip().upper()
            user = {"user_id": row[0], "name": row[1], "role": role}
            # ROLE에 따라 환영 메시지 구분
            if role == "ADMIN":
                print(f"  ✅ 관리자 {user['name']} 님으로 로그인되었습니다.")
            else:
                print(f"  ✅ 환영합니다, {user['name']} 님!")
            return user
        else:
            print("  ❌ 이름 또는 비밀번호가 올바르지 않습니다.")
            return None
    except Exception as e:
        print(f"  ❌ 로그인 오류 → {str(e)}")
        return None
    finally:
        cursor.close()


# ──────────────────────────────────────────────
# 관리자 시드 계정 (최초 1회)
# ──────────────────────────────────────────────

def seed_admin(conn):
    """
    기본 관리자 계정 생성 (중복 시 스킵).
    - 이름: admin, ROLE: ADMIN, 비밀번호는 코드 내 상수(아래 pwd_plain)로 1회 해시 저장
    - 초기 비밀번호 평문은 터미널에 출력하지 않음 → 개발 시 pwd_plain 값을 참고할 것
    """
    pwd_plain = "1234"  # 최초 seed 전용; 운영에서는 반드시 변경
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM   USERS
            WHERE  NAME = :admin_name
              AND  ROLE = :admin_role
            """,
            {"admin_name": "admin", "admin_role": "ADMIN"}
        )
        if cursor.fetchone()[0] > 0:
            print("  (안내) 관리자 계정(admin)이 이미 존재합니다. seed 생략.")
            return

        pwd_hash = hash_password(pwd_plain)
        cursor.execute(
            """
            INSERT INTO USERS (USER_ID, NAME, PWD_HASH, ROLE, IS_DELETED, CREATED_AT)
            VALUES (SEQ_USER_ID.NEXTVAL, :admin_name, :pwd_hash, :admin_role, :is_deleted, SYSDATE)
            """,
            {
                "admin_name": "admin",
                "pwd_hash": pwd_hash,
                "admin_role": "ADMIN",
                "is_deleted": "N",
            }
        )
        conn.commit()
        # 초기 비밀번호는 화면에 노출하지 않음(과제/내부 문서에서만 안내)
        print("  ✅ 관리자 계정(admin)이 생성되었습니다. (초기 비밀번호는 auth.seed_admin 의 pwd_plain 참고)")
    except Exception as e:
        conn.rollback()
        print(f"  ❌ seed_admin 실패 → {str(e)}")
    finally:
        cursor.close()


# ──────────────────────────────────────────────
# 관리자용 회원 관리
# ──────────────────────────────────────────────

def admin_list_users(conn):
    """전체 회원 조회: USER_ID, NAME, ROLE, IS_DELETED, CREATED_AT"""
    print("\n=== [ 전체 회원 조회 ] ===")
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT USER_ID, NAME, ROLE, IS_DELETED, CREATED_AT
            FROM   USERS
            ORDER BY USER_ID
            """
        )
        rows = cursor.fetchall()
        if not rows:
            print("  (없음) 등록된 회원이 없습니다.")
            return
        print(f"\n  {'ID':<6} {'이름':<12} {'ROLE':<8} {'삭제':<6} {'가입일시'}")
        print("  " + "-" * 60)
        for r in rows:
            uid, name, role, is_del, created = r
            ct = created.strftime("%Y-%m-%d %H:%M") if created else "-"
            print(f"  {uid:<6} {str(name or ''):<12} {str(role or ''):<8} {str(is_del or ''):<6} {ct}")
    except Exception as e:
        print(f"  ❌ 조회 실패 → {str(e)}")
    finally:
        cursor.close()


def admin_search_user(conn, raw_query=None):
    """
    이름 또는 USER_ID로 회원 검색 (숫자면 ID, 아니면 이름).
    - raw_query: main.py 등에서 미리 검증한 검색어를 넘기면 input 생략
    """
    print("\n=== [ 회원 검색 ] ===")
    if raw_query is not None:
        raw = str(raw_query).strip()
    else:
        raw = input("  검색어 (USER_ID 숫자 또는 이름): ").strip()
    if not raw:
        print("  ❌ 검색어를 입력하세요.")
        return
    cursor = conn.cursor()
    try:
        if raw.isdigit():
            cursor.execute(
                """
                SELECT USER_ID, NAME, ROLE, IS_DELETED, CREATED_AT
                FROM   USERS
                WHERE  USER_ID = :search_uid
                """,
                {"search_uid": int(raw)}
            )
            one = cursor.fetchone()
            rows = [one] if one else []
        else:
            cursor.execute(
                """
                SELECT USER_ID, NAME, ROLE, IS_DELETED, CREATED_AT
                FROM   USERS
                WHERE  NAME LIKE :search_pattern
                ORDER BY USER_ID
                """,
                {"search_pattern": f"%{raw}%"}
            )
            rows = cursor.fetchall()
        if not rows:
            if raw.isdigit():
                print("  존재하지 않는 회원입니다.")
            else:
                print("  검색 결과가 없습니다.")
            return
        print(f"\n  {'ID':<6} {'이름':<12} {'ROLE':<8} {'삭제':<6} {'가입일시'}")
        print("  " + "-" * 60)
        for r in rows:
            uid, name, role, is_del, created = r
            ct = created.strftime("%Y-%m-%d %H:%M") if created else "-"
            print(f"  {uid:<6} {str(name or ''):<12} {str(role or ''):<8} {str(is_del or ''):<6} {ct}")
    except Exception as e:
        print(f"  ❌ 검색 실패 → {str(e)}")
    finally:
        cursor.close()


def admin_soft_delete_user(conn, admin_user, target_uid=None):
    """
    회원 소프트 삭제: IS_DELETED = 'Y'
    - 관리자 본인 계정은 삭제 불가
    - target_uid: main.py 에서 DB 존재 확인 후 넘기면 USER_ID 입력 생략
    """
    print("\n=== [ 회원 삭제(소프트) ] ===")
    if target_uid is not None:
        if not isinstance(target_uid, int):
            print("  ❌ 잘못된 USER_ID입니다.")
            return
    else:
        raw = input("  삭제 처리할 USER_ID: ").strip()
        if not raw or not raw.isdigit():
            print("  ❌ 숫자 USER_ID를 입력하세요.")
            return
        target_uid = int(raw)
    if target_uid == admin_user["user_id"]:
        print("  ❌ 관리자 본인 계정은 삭제할 수 없습니다.")
        return

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT USER_ID, NAME, IS_DELETED, ROLE
            FROM   USERS
            WHERE  USER_ID = :target_uid
            """,
            {"target_uid": target_uid}
        )
        row = cursor.fetchone()
        if row is None:
            print("  존재하지 않는 회원입니다.")
            return
        if str(row[2]).strip().upper() == "Y":
            print("  (안내) 이미 삭제 처리된 회원입니다.")
            return

        cursor.execute(
            """
            UPDATE USERS
            SET    IS_DELETED = :del_flag
            WHERE  USER_ID    = :target_uid
            """,
            {"del_flag": "Y", "target_uid": target_uid}
        )
        conn.commit()
        print(f"  ✅ USER_ID {target_uid} ({row[1]}) 회원을 삭제 처리했습니다.")
    except Exception as e:
        conn.rollback()
        print(f"  ❌ 삭제 처리 실패 → {str(e)}")
    finally:
        cursor.close()


def admin_restore_user(conn, admin_user, target_uid=None):
    """
    회원 복구: IS_DELETED = 'N'
    - target_uid: main.py 에서 DB 존재 확인 후 넘기면 USER_ID 입력 생략
    """
    print("\n=== [ 회원 복구 ] ===")
    if target_uid is not None:
        if not isinstance(target_uid, int):
            print("  ❌ 잘못된 USER_ID입니다.")
            return
    else:
        raw = input("  복구할 USER_ID: ").strip()
        if not raw or not raw.isdigit():
            print("  ❌ 숫자 USER_ID를 입력하세요.")
            return
        target_uid = int(raw)

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT USER_ID, NAME, IS_DELETED
            FROM   USERS
            WHERE  USER_ID = :target_uid
            """,
            {"target_uid": target_uid}
        )
        row = cursor.fetchone()
        if row is None:
            print("  존재하지 않는 회원입니다.")
            return
        if str(row[2]).strip().upper() != "Y":
            print("  (안내) 삭제 상태가 아닌 회원입니다. 복구할 필요가 없습니다.")
            return

        cursor.execute(
            """
            UPDATE USERS
            SET    IS_DELETED = :ok_flag
            WHERE  USER_ID    = :target_uid
            """,
            {"ok_flag": "N", "target_uid": target_uid}
        )
        conn.commit()
        print(f"  ✅ USER_ID {target_uid} ({row[1]}) 회원을 복구했습니다.")
    except Exception as e:
        conn.rollback()
        print(f"  ❌ 복구 실패 → {str(e)}")
    finally:
        cursor.close()


# ──────────────────────────────────────────────
# 2차 보안 인증 (F-08)
# ──────────────────────────────────────────────

def request_second_auth(conn, user_id, trans_id):
    """
    2차 인증 코드 발급.
    - USER_ID 컬럼 값은 :auth_user_id 로 바인드 (:user_id 단독 사용 회피)
    """
    code      = generate_auth_code()
    expire_at = datetime.now() + timedelta(minutes=3)

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO SECURITY_AUTH
                (AUTH_ID, TRANS_ID, USER_ID, AUTH_CODE, ATTEMPTS,
                 METHOD, EXPIRE_AT, STATUS)
            VALUES
                (SEQ_AUTH_ID.NEXTVAL, :trans_id, :auth_user_id, :auth_code,
                 0, :auth_method, :expire_at, :auth_status)
            """,
            {
                "trans_id": trans_id,
                "auth_user_id": user_id,
                "auth_code": code,
                "expire_at": expire_at,
                "auth_method": "APP",
                "auth_status": "PENDING",
            }
        )
        conn.commit()
        print(f"\n  [2차 인증] 발급된 코드: {code}  (유효시간: 3분)")
        return code, expire_at
    except Exception as e:
        conn.rollback()
        print(f"  ❌ 2차 인증 발급 오류 → {str(e)}")
        return None, None
    finally:
        cursor.close()

def verify_second_auth(conn, trans_id, input_code):
    """2차 인증 검증. STATUS 문자열은 모두 바인드."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT AUTH_ID, AUTH_CODE, ATTEMPTS, EXPIRE_AT, STATUS
            FROM   SECURITY_AUTH
            WHERE  TRANS_ID = :trans_id
              AND  STATUS   = :status_pending
            ORDER BY AUTH_ID DESC
            FETCH FIRST 1 ROW ONLY
            """,
            {"trans_id": trans_id, "status_pending": "PENDING"}
        )
        row = cursor.fetchone()

        if not row:
            print("  ❌ 유효한 인증 정보를 찾을 수 없습니다.")
            return False

        auth_id, auth_code, attempts, expire_at, status = row

        if not verify_auth_time(expire_at):
            cursor.execute(
                """
                UPDATE SECURITY_AUTH
                SET    STATUS = :new_status
                WHERE  AUTH_ID = :auth_id
                """,
                {"new_status": "EXPIRED", "auth_id": auth_id}
            )
            conn.commit()
            print("  ❌ 인증 코드가 만료되었습니다.")
            return False

        if input_code == auth_code:
            cursor.execute(
                """
                UPDATE SECURITY_AUTH
                SET    STATUS = :new_status
                WHERE  AUTH_ID = :auth_id
                """,
                {"new_status": "VERIFIED", "auth_id": auth_id}
            )
            conn.commit()
            print("  ✅ 2차 인증 성공!")
            return True

        new_attempts = attempts + 1
        if new_attempts >= 3:
            cursor.execute(
                """
                UPDATE SECURITY_AUTH
                SET    ATTEMPTS = :attempts,
                       STATUS   = :new_status
                WHERE  AUTH_ID = :auth_id
                """,
                {"attempts": new_attempts, "new_status": "BLOCKED", "auth_id": auth_id}
            )
            conn.commit()
            print("  ❌ 인증 3회 실패 - 거래가 차단되었습니다.")
        else:
            cursor.execute(
                """
                UPDATE SECURITY_AUTH
                SET    ATTEMPTS = :attempts
                WHERE  AUTH_ID = :auth_id
                """,
                {"attempts": new_attempts, "auth_id": auth_id}
            )
            conn.commit()
            print(f"  ❌ 인증 실패 ({new_attempts}/3회). 다시 시도하세요.")
        return False
    except Exception as e:
        conn.rollback()
        print(f"  ❌ 인증 검증 오류 → {str(e)}")
        return False
    finally:
        cursor.close()
