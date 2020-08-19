#!/usr/bin/env bash
set -e 
export DJANGO_SETTINGS_MODULE=settings
export PYTHONPATH=/srv/zeus_app

cd /srv/zeus_app

for DIR in election_logs mixes results static media poll_reports proofs media media/zeus_mixes;
do
    if [ ! -d "/srv/zeus-data/$DIR" ];
    then
        mkdir -p /srv/zeus-data/${DIR}
    fi
done

until pg_isready -h db; do sleep 2; done

python manage.py makemigrations --noinput
python manage.py makemigrations helios --noinput
python manage.py makemigrations heliosauth --noinput
python manage.py makemigrations zeus --noinput
python manage.py migrate --noinput
python manage.py collectstatic --noinput -l

python init_admin.py GRNET admin admin

mkdir -p /var/run/celery/
mkdir -p /var/log/celery/
C_FORCE_ROOT=1 python manage.py celery worker --pidfile=/var/run/celery/w1.pid -n w1@zeus-docker --workdir=/srv/zeus_app --logfile=/srv/zeus-data/celery.log &

tail -f /srv/zeus-data/zeus.log &

gunicorn wsgi \
    --bind=[::]:${OPTION_GUNICORN_PORT} \
    --workers=${OPTION_GUNICORN_WORKERS} \
    --worker-tmp-dir=/dev/shm \
    --reload \
    --log-level=$LOG_LEVEL \
    --log-file=- \
    --access-logfile=-
