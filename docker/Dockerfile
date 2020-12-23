#from balenalib/raspberry-pi-python
FROM python:buster  

COPY . /opt/diyca/
#COPY app_web /opt/diyca/app_web
#COPY bin /opt/diyca/bin
#COPY docs /opt/diyca/docs
#COPY diyca.version /opt/diyca/


RUN apt update && apt-get install -y --no-install-recommends openssl sqlite3 rsyslog && pip3 install flask dnspython pyOpenSSL werkzeug
# Prevent any rsyslog errors
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf && touch /dev/log

WORKDIR /opt/diyca

RUN service rsyslog restart && /opt/diyca/bin/1.diyca_cleanup.sh && /opt/diyca/bin/2.diyca_calvin_init.sh && /opt/diyca/bin/3.diyca_web_init.sh

ENTRYPOINT cd app_web && python3 diyca_web_main.py