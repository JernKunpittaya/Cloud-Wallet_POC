import React, { Component } from "react";
//Here is dev
import "./App.css";
import LocalBob from "./components/LocalBob";
class App extends Component {
  render() {
    return (
      <div className="App">
        <LocalBob />
      </div>
    );
  }
}
export default App;
