# DIYCA Docker

As raspberry pi is capable of docker I had the idea running diyca in a container. 

The install was not as easy as I had it in mind. To keep the trouble form any one in future I will write a small docker part for this project. 

## General 

You can build the image with docker build. 
This will produce an runnning container hosting what ever is in your actual configs. 
The configuration will be copied over. 

To make this more portable and keep your configs you may want to build a docker compse.
This should bind mount the config and certs dir. After this you need to re run the init steps. 


## x86
Is using a base docker. This will be usefull to test or make this happen on your server/nas

## RPI 
Is made for running on an RPI1. This can be adopted changing the base image (from line)
This will capsulate up the image and be helpfull if you use the pi for more than one application.
