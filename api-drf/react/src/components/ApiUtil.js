import axios from 'axios'

axios.defaults.xsrfCookieName = 'csrftoken'
axios.defaults.xsrfHeaderName = 'X-CSRFTOKEN'

const Api = axios.create({
  baseURL: `/api`
})

Api.interceptors.response.use(response => {
  return response;
}, (err) => {
  if (err.response.status === 401) {
    localStorage.removeItem("username")
    window.location.hash = "/login"
  }
  return Promise.reject(err);
});

export default Api
