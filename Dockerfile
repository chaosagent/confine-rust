FROM ubuntu:16.04

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y software-properties-common curl file sudo build-essential
RUN apt-get install -y openjdk-7-jdk
RUN apt-get install -y python2.7 python3.5
RUN add-apt-repository ppa:openjdk-r/ppa


RUN curl -s https://static.rust-lang.org/rustup.sh | sh -s -- --channel=nightly
RUN mkdir /app
COPY . /app
WORKDIR /app

RUN cargo build

RUN cp /app/target/debug/confine /usr/bin/confine