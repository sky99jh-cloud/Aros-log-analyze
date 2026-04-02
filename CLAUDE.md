# Cimon ALog Analyzer

Cimon for Windows (KDT) `.ALog` 바이너리 파일에서 텍스트를 추출하고, D/H 장치의 동작 주기를 분석하는 GUI 도구.

## 실행

```bash
python alog_analyzer.py
```

- Python 3.x, 표준 라이브러리 + tkinter만 사용 (외부 패키지 없음)
- Windows 전용 (cp949 인코딩, Malgun Gothic 폰트)

## 파일 구조

```
AROS 로그 분석/
├── alog_analyzer.py   # 전체 소스 (파싱 + UI, 단일 파일)
├── CLAUDE.md
└── log/               # 샘플 로그 폴더
```

## 핵심 구조

### 파싱 (`alog_analyzer.py` 상단 ~170줄)

| 함수 | 역할 |
|------|------|
| `unix_to_kst(ts)` | Unix timestamp → KST datetime 변환 (유효범위 검증 포함) |
| `parse_alog(filepath)` | `.ALog` 바이너리를 1바이트씩 스캔, Little-endian 4바이트 타임스탬프 위치마다 레코드 분리 |
| `extract_text_records(records)` | cp949 디코딩 후 정규식으로 가독 텍스트 추출, 이벤트 유형(경보/동작/복귀/시각변경) 분류 |
| `find_dh_devices(records)` | 레코드 전체에서 `D/H_\w+` 패턴 장치명 수집 |
| `calc_cycles(events)` | 이벤트 목록을 2개씩 쌍(시작/종료)으로 묶어 동작시간·대기시간·주기 계산 |

### `calc_cycles` 로직 주의사항

```
events = [t0, t1, t2, t3, ...]
pairs  = [(t0,t1), (t2,t3), ...]   # 짝수 인덱스 기준 2개씩 쌍
동작시간 = end - start
대기시간 = 다음쌍.start - end
주기     = 다음쌍.start - start
```

**전제**: "동작" 로그가 시작/종료 각 1회씩 정확히 쌍으로 발생해야 함.  
로그 누락·중복 시 시작/종료 역전 가능.

### UI (`App` 클래스, 170줄~끝)

5개 탭 구성:

| 탭 | 내용 |
|----|------|
| 동작 주기 분석 | 키워드 필터(기본 `D/H_7` + `동작`)로 이벤트 추출, 테이블·통계 카드 표시 |
| 알람 로그 | 전체 텍스트 레코드 뷰, TXT 저장 |
| 동작 그래프 | 장치별 타임라인 캔버스 (단일/멀티 레인) |
| 일별 분석 | D/H 장치별 날짜별 막대 그래프 (동작 횟수 / 총 동작 시간 모드) |
| 요약 통계 | 전체 통계 텍스트 요약 |

### 파일 불러오기 방식

- **파일 열기**: 단일 `.ALog` 파일 직접 선택
- **폴더 열기**: 폴더 내 모든 `.ALog` 파일 일괄 로드 → 연도/월 선택 다이얼로그로 해당 월 데이터만 필터링

## 데이터 흐름

```
.ALog 바이너리
  └─ parse_alog()          → records: [(datetime, bytes), ...]
       ├─ extract_text_records() → text_rows (알람 로그 탭)
       ├─ find_dh_devices()      → dh_devices 목록
       └─ _run_cycle_analysis()
            └─ calc_cycles()     → cycle_rows (주기 분석 탭·그래프·일별)
```

## CSV 출력 컬럼

`동작주기_분석.csv`:  
`번호, 시작, 종료, 동작시간(초), 동작시간(분), 대기시간(초), 대기시간(분), 주기(초), 주기(분)`

---

## 변경 이력

### 2026-04-02

- **일별 분석 날짜 레이블 수평 표시**  
  `_draw_daily_graph()` 내 날짜 레이블의 `angle=45, anchor="nw"` 제거 → `anchor="n"` 으로 변경.  
  막대 그래프 하단 날짜(MM/DD)가 겹쳐 보이던 문제 수정.

- **전체 D/H 그래프 동작 시간 텍스트 제거**  
  `_draw_multi_lane_graph()` 내 블록 위 동작 시간 레이블(세로/가로 텍스트) 표시 코드 삭제.  
  블록이 좁을 때 겹쳐 보이는 문제 해소.

- **헤더 바이트 오탐 타임스탬프 제거**  
  `parse_alog()`에서 바이너리 헤더의 임의 바이트가 유효 Unix timestamp 범위(`1700000000~1900000000`)에 우연히 걸려 이상한 날짜(2028, 2029년 등) 레코드로 표시되던 문제 수정.  
  파싱 후 최빈(modal) 날짜를 기준으로 ±7일 밖 레코드를 자동 제거하는 필터 추가.
