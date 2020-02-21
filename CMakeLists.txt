cmake_minimum_required(VERSION 3.10)

# set the project name
project(TrafficStat)


# add the executable
add_executable(traffic_stat main.c stat.c util.c)

target_link_libraries(traffic_stat pcap)