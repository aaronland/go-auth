# https://blog.docker.com/2016/09/docker-golang/
# https://blog.golang.org/docker

# docker build -t ucd-username .
# docker run -p 6161:8080 -e HOST='0.0.0.0' ucd-username

# build phase - see also:
# https://medium.com/travis-on-docker/multi-stage-docker-builds-for-creating-tiny-go-images-e0e1867efe5a
# https://medium.com/travis-on-docker/triple-stage-docker-builds-with-go-and-angular-1b7d2006cb88

FROM golang:alpine AS build-env

RUN apk add --update alpine-sdk

ADD . /go-ucd-username

RUN cd /go-ucd-username; make bin

FROM alpine

COPY --from=build-env /go-ucd-username/bin/ucd-usernamed /ucd-usernamed

EXPOSE 8080

CMD /ucd-usernamed -host ${HOST}
