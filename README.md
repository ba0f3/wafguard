# haproxy-waf-spoe

Dịch vụ Go SPOA cho HAProxy, kết hợp verdict từ **Coraza SPOA upstream nguyên bản** với HTTP response và hành vi nhiều request để phát hiện scanner, brute force, burst và quản lý ban có thời hạn trên toàn cụm.

## Trạng thái

Repository đang ở giai đoạn specification; chưa có service implementation hoặc binary production. Coraza baseline: official `corazawaf/coraza-spoa` v0.9.1, commit `c9b34f409e04cfb60219602bd1ad711afd15eaa3`.

## Tài liệu

- [Thiết kế v2: Coraza upstream nguyên bản](docs/specs/2026-11-23-haproxy-waf-spoe-design.md) — contract SPOE, thứ tự event, Redis, policies, vận hành và acceptance gates.

## Định hướng

- Coraza kiểm tra payload; service này kết hợp verdict với hành vi và quản lý ban.
- Không sửa hoặc duy trì fork Coraza; core không phụ thuộc log enrichment.
- P0 kiểm tra shared Redis trước mỗi HTTP request, không local cache.
- Không tự ban chỉ vì 5xx; rollout bắt đầu bằng observe mode.
- Toàn bộ behavioral core, adapters và admin API được phát triển trong repository này.
