#!/bin/bash


export FLASK_APP=vpnconfig

flask run --host=0.0.0.0 > flask.log


