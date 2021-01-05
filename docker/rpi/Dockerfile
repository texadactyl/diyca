FROM balenalib/raspberry-pi

COPY . /opt/diyca/

RUN apt update && apt-get install -y --no-install-recommends openssl sqlite3 rsyslog python3 python3-pip python3-openssl python3-cffi-backend && pip3 install flask dnspython 
# Prevent any rsyslog errors
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf && touch /dev/log

WORKDIR /opt/diyca

RUN service rsyslog restart && /opt/diyca/bin/1.diyca_cleanup.sh && /opt/diyca/bin/2.diyca_calvin_init.sh && /opt/diyca/bin/3.diyca_web_init.sh

ENTRYPOINT cd app_web && python3 diyca_web_main.py
