FROM alpine:3.20 AS builder

WORKDIR /src
COPY . .

RUN apk add --no-cache bash git patch \
    && patch -p1 < patches/rex-fallback-fields.patch \
    && bash scripts/build.alpine.release.sh

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /base
COPY --from=builder /src/subconverter/ /base/

EXPOSE 25500
CMD ["./subconverter"]
