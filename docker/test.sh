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

service postgresql start
until pg_isready; do sleep 2; done

echo $*;
python manage.py test $*;