FROM debian:jessie

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y gettext postgresql-client

RUN apt-get install -y ttf-dejavu ttf-dejavu-core ttf-dejavu-extra 
RUN apt-get install -y python2.7 python-setuptools
RUN apt-get install -y python-amqp python-amqplib python-bleach python-celery python-chardet 
RUN apt-get install -y python-crypto python-dateutil python-django 
RUN apt-get install -y python-django-celery python-django-mptt python-django-pagination 
RUN apt-get install -y python-django-picklefield python-django-south python-gmpy
RUN apt-get install -y python-kombu python-lxml python-markdown
RUN apt-get install -y python-openid python-psycopg2 python-pyicu 
RUN apt-get install -y python-pyparsing python-reportlab python-reportlab-accel
RUN apt-get install -y python-stdnum
RUN apt-get install -y python-yaml python-pip
RUN apt-get install -y gunicorn

# dev related
RUN apt-get install -y vim ipython
RUN apt-get install -y python-pytest
RUN apt-get install -y python-freezegun
RUN pip install pytest-django==2.7.0

RUN apt-get install -y wget
RUN wget https://github.com/Yelp/dumb-init/releases/download/v1.2.2/dumb-init_1.2.2_amd64.deb
RUN dpkg -i dumb-init_*.deb

RUN pip install django-environ==0.4.5

RUN apt-get install -y celeryd
RUN echo 'CELERYD_CHDIR=/srv/zeus_app' >> /etc/default/celeryd
RUN echo 'CELERYD_MULTI="\$CELERYD_CHDIR/manage.py celeryd_multi"' >> /etc/default/celeryd
RUN echo 'CELERYCTL="\$CELERYD_CHDIR/manage.py celeryctl"' >> /etc/default/celeryd
RUN echo 'export DJANGO_SETTINGS_MODULE="settings"' >> /etc/default/celeryd
RUN echo 'ENABLED=true' >> /etc/default/celeryd

RUN mkdir /storage/

ENV PYTHONUNBUFFERED 1

RUN mkdir /srv/zeus_app

COPY . /srv/zeus_app/
WORKDIR /srv/zeus_app

VOLUME /srv/zeus-data

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

ENV PYTHONPATH=/srv/zeus_app
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/srv/zeus_app/docker/entrypoint.sh"]
