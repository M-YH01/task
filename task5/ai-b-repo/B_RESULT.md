# AI B 결과 (HANDOFF.md는 A 원본 그대로 보존)

- 시각(UTC): 첫 시도 07:31:22(웹 다운로드 403 실패) → 로컬 수신 07:36:20 → 종료 2026-09-15T07:38:35Z
- 도구 호출: 20 / 80 (첫 시도 4 포함). 토큰 사용량은 노출되지 않음
- 수신 HANDOFF.md SHA-256: 784da868…3709a — 사용자 제시 기대값·handoff-manifest.json과 일치 (receive.cjs 13개 파일 모두 일치)
- 재현: 새 폴더(ai-b-work), Node v24.21.0, 8/10, 종료 코드 1, index.html 814d8bf2… 일치
- 최종: 10/10, 종료 코드 0, index.html 83614a68433d6b76a28cec2712b2fa19b99cdcba02f6ee49f2cc6db5cf87eecf
- 오류 회차(검사 10개 중 1개 이상 실패한 실행): 1회 (최초 재현 실행)
- 대화 전문: 제공되지 않음. 같은 세션의 첫 시도 기록에는 HANDOFF 요약만 있었고 소스는 없었음

## 변경 (index.html restoreFromProject만)
1. 검증 통과 후 비율·문구를 임시 값으로 준비하고 commit()에서 한 번에 적용
2. 이미지가 있으면 onload 이후에만 적용하고, onerror면 상태를 바꾸지 않은 채 오류만 표시(T09)
3. 성공 알림은 적용 후 1회만 표시(T10). 적용 시 이전 오류 배너 제거
4. 연속 복원 시 더 새로운 복원이 시작되면 이전 이미지의 늦은 load/error를 무시(순번 토큰)

## 브라우저 확인 (evidence/b-browser-check.json, tools/b-browser-check.cjs)
Headless Chromium에서 파일 입력으로 확인. 정상 JSON, PNG 포함, 손상 JSON, 디코딩 실패 PNG, 연속 복원 2건 모두 기대대로였고 페이지 오류는 0건. 이후 직접 화면 보면서 확인 완료.

## 미확인·한계
- 연속 복원 토큰은 논리로만 보강. 브라우저 확인에서는 첫 이미지가 먼저 디코딩돼 실제 경쟁 상태가 재현되지 않았음
- AI 조건(사용자 확인): A와 B는 다른 서비스·모델로 충족. 단, B는 무료가 아니라 Pro(유료) 요금제여서 과제 4의 "무료 AI B" 조건은 미충족. 자세한 내용은 TIMELINE.md
