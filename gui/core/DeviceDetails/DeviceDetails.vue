<template>
  <div id="device-details">
    <div class="row">
      <div class="col-md-2" style="text-align:center">
        <device-icon :type=device.type size=54 />
        <br>
        {{ device.name }}
        <br>
        <ul class="messages">
          <li v-for="e in exceptions" :key=e.identifier>
            <b-alert variant="danger" show dismissible fade>{{ e.config.url }}<br>{{ e.status }} {{ e.statusText }}:<br> {{ e.data.message }}</b-alert>
          </li>
        </ul>

      </div>
      <div class="col-md-6">
          <b-tabs content-class="mt-3">
          <b-tab title="Installed Applications" active>
            <ul class="application-list-items">
              <applications-list-item
                v-for="app in installed_apps"
                :key=app.identifier
                :device=device
                :application=app
                class="application-list-item"
              />
            </ul>
          </b-tab>
          <b-tab title="Running Processes">
            <ul class="application-list-items">
              <applications-list-item
                v-for="app in running_procs"
                :key=app.identifier
                :device=device
                :application=app
                class="application-list-item"
              />
            </ul>
          </b-tab>
        </b-tabs>
      </div>
      <div class="col-md-4">
        <div class="row">
          <div id="settings-sidebar-icon">
            <SettingsIcon />
            Advanced Settings
          </div>
        </div>

        <div id="settings-sidebar" class="sidebar">
          <div class="row">
            <a href="javascript:void(0)" class="closebtn" onclick="closeNav()">&times;</a>
            <div style="float:right">
              <i class="material-icons">save</i>
            </div>
          </div>
          <h6>Modules</h6>
          <ul style="list-style-type:none">
            <li>
              <input type="checkbox" checked> module #1
              <i class="material-icons" style="font-size:14px;cursor:pointer;">settings</i>
            </li>
            <li>
              <input type="checkbox" checked>module #2
              <i class="material-icons" style="font-size:14px;cursor:pointer;">settings</i>
            </li>
            <li>
              <input type="checkbox" checked>module #3
              <i class="material-icons" style="font-size:14px;cursor:pointer;">settings</i>
            </li>
            <li>
              <input type="checkbox">module #4
              <i class="material-icons" style="font-size:14px;cursor:pointer;">settings</i>
            </li>
            <li>
              <input type="checkbox">module #5
              <i class="material-icons" style="font-size:14px;cursor:pointer;">settings</i>
            </li>
            <li>
              <input type="checkbox">module #6
              <i class="material-icons" style="font-size:14px;cursor:pointer;">settings</i>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'
import DeviceIcon from '../DeviceIcon/DeviceIcon.vue'
import ApplicationsListItem from './ApplicationsListItem.vue'
import SettingsIcon from 'vue-material-design-icons/Settings.vue'

export default {
  name: "app",
  props: ["id"],
  components: {
    DeviceIcon,
    ApplicationsListItem,
    SettingsIcon
  },
  data() {
    return {
      device: {
        id: ""
      },
      installed_apps: [],
      running_procs: [],
      sidebar_open: false,
      exceptions: []
    };
  },
  mounted() {
    axios
      .get(
        "http://localhost:5000/api/v1/device/details?device_id=" +
          this.$route.params.id
      )
      .catch(error => (this.exceptions.push(error.response)))
      .then(response => (this.device = response.data));
    axios
      .get(
        "http://localhost:5000/api/v1/device/applications?device_id=" +
          this.$route.params.id
      )
      .catch(error => (this.exceptions.push(error.response)))
      .then(response => (this.installed_apps = response.data));
    axios
      .get(
        "http://localhost:5000/api/v1/device/processes?device_id=" +
          this.$route.params.id
      )
      .catch(error => (this.exceptions.push(error.response)))
      .then(response => (this.running_procs = response.data));
  },
  methods: {
    toggle() {
      this.sidebar_open = !this.sidebar_open;
    }
  }
};
</script>

<style>
  .messages {
    list-style-type: none;
    padding: 4%;
    /* margin: 0; */
  }
  .sidebar {
      height: 100%; /* 100% Full-height */
      width: 0; /* 0 width - change this with JavaScript */
      position: fixed; /* Stay in place */
      z-index: 1; /* Stay on top */
      top: 0;
      right: 0;
      background-color: #fff;
      overflow-x: hidden;
      padding-top: 60px;
      transition: 0.5s;
      border-left: 1px solid #eee;
  }

  /* The sidebar links */
  .sidebar a {
      padding: 8px 8px 8px 32px;
      text-decoration: none;
      font-size: 25px;
      color: #818181;
      display: block;
      transition: 0.3s;
  }

      /* When you mouse over the navigation links, change their color */
  .sidebar a:hover {
      color: #000;
  }

      /* Position and style the close button (top right corner) */
  .sidebar .closebtn {
      position: absolute;
      top: 0;
      left: 0;
      font-size: 36px;
      margin-left: 0;
  }

      /* The button used to open the sidebar */
  .openbtn {
      font-size: 20px;
      cursor: pointer;
      background-color: #111;
      color: white;
      padding: 10px 15px;
      border: none;
  }

  .openbtn:hover {
      background-color: #444;
  }

      /* Style page content - use this if you want to push the page content to the right when you open the side navigation */
  #settings-sidebar-icon {
      transition: margin-right .5s; /* If you want a transition effect */
      padding: 20px;
      float: right;
  }

      /* On smaller screens, where height is less than 450px, change the style of the sidenav (less padding and a smaller font size) */
  @media screen and (max-height: 450px) {
      .sidebar {padding-top: 15px;}
      .sidebar a {font-size: 18px;}
  }
</style>
