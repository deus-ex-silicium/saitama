<template>
                <div id="device-list-component">
                    <h1>Saitama</h1>
                    <p>Select a device to be beaten by the Master.</p>

                    <img :src="require('./assets/shiny.jpg')" />

                    <div>
                        <ul class="device-list-items">
                            <devices-list-item v-for="device in devices.data" v-bind:key="device.id" v-bind:device="device"
 class="device-list-item" />
                        </ul>
                    </div>
                </div>
</template>

<script>
import axios from 'axios'
import DevicesListItem from './DevicesListItem.vue'

export default {
  name: 'devices-list',
  components: {
    DevicesListItem,
  },
            data() {
                return {
                    devices: [],
                }
            },
            mounted() {
                axios
                    .get('http://localhost:5000/api/v1/devices')
                    .then(response => this.devices = response)
            },
}
</script>

<style>
        body {
            background-color: #f0f0f2;
            margin: 0;
            padding: 0;
            font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        }

        a:link,
        a:visited {
            color: #38488f;
            text-decoration: none;
        }
        @media (max-width: 700px) {
            div {
                margin: 0 auto;
                width: auto;
            }
        }

        #device-list-component {
            width: 600px;
            min-height: 700px;
            margin: 20px auto 0 auto;
            padding: 2em;
            background-color: #fdfdff;
            border-radius: 0.5em;
            box-shadow: 2px 3px 7px 2px rgba(0, 0, 0, 0.02);
        }

        img {
            height: 100%;
            width: 100%;
            object-fit: contain;
        }

        ul.device-list-items {
            margin-top:60px;
        }

        .device-list-item {
            list-style-type: none;
            float: left;
            display: block;
            width: 120px;
            height: 110px;
            cursor: pointer;
            margin: 0 0 0 15px;
            text-align: center;
        }

        a.router-link {
            color: inherit;
        }

        a.router-link:hover {
            color: #612929;
        }

        #device-details {
            
        }
</style>
