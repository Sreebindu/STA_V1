"use strict";
/*
 * ATTENTION: An "eval-source-map" devtool has been used.
 * This devtool is neither made for production nor for readable output files.
 * It uses "eval()" calls to create a separate source file with attached SourceMaps in the browser devtools.
 * If you are trying to read the output file, select a different devtool (https://webpack.js.org/configuration/devtool/)
 * or disable the default devtool with "devtool: false".
 * If you are looking for production-ready output files, see mode: "production" (https://webpack.js.org/configuration/mode/).
 */
exports.id = "vendor-chunks/react-leaflet";
exports.ids = ["vendor-chunks/react-leaflet"];
exports.modules = {

/***/ "(ssr)/./node_modules/react-leaflet/lib/hooks.js":
/*!*************************************************!*\
  !*** ./node_modules/react-leaflet/lib/hooks.js ***!
  \*************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

eval("__webpack_require__.r(__webpack_exports__);\n/* harmony export */ __webpack_require__.d(__webpack_exports__, {\n/* harmony export */   useMap: () => (/* binding */ useMap),\n/* harmony export */   useMapEvent: () => (/* binding */ useMapEvent),\n/* harmony export */   useMapEvents: () => (/* binding */ useMapEvents)\n/* harmony export */ });\n/* harmony import */ var _react_leaflet_core__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @react-leaflet/core */ \"(ssr)/./node_modules/@react-leaflet/core/lib/context.js\");\n/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ \"(ssr)/./node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js\");\n\n\nfunction useMap() {\n    return (0,_react_leaflet_core__WEBPACK_IMPORTED_MODULE_1__.useLeafletContext)().map;\n}\nfunction useMapEvent(type, handler) {\n    const map = useMap();\n    (0,react__WEBPACK_IMPORTED_MODULE_0__.useEffect)(function addMapEventHandler() {\n        // @ts-ignore event type\n        map.on(type, handler);\n        return function removeMapEventHandler() {\n            // @ts-ignore event type\n            map.off(type, handler);\n        };\n    }, [\n        map,\n        type,\n        handler\n    ]);\n    return map;\n}\nfunction useMapEvents(handlers) {\n    const map = useMap();\n    (0,react__WEBPACK_IMPORTED_MODULE_0__.useEffect)(function addMapEventHandlers() {\n        map.on(handlers);\n        return function removeMapEventHandlers() {\n            map.off(handlers);\n        };\n    }, [\n        map,\n        handlers\n    ]);\n    return map;\n}\n//# sourceURL=[module]\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiKHNzcikvLi9ub2RlX21vZHVsZXMvcmVhY3QtbGVhZmxldC9saWIvaG9va3MuanMiLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7QUFBd0Q7QUFDdEI7QUFDM0I7QUFDUCxXQUFXLHNFQUFpQjtBQUM1QjtBQUNPO0FBQ1A7QUFDQSxJQUFJLGdEQUFTO0FBQ2I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQSxJQUFJLGdEQUFTO0FBQ2I7QUFDQTtBQUNBO0FBQ0E7QUFDQSxLQUFLO0FBQ0w7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsInNvdXJjZXMiOlsiL2hvbWUvZXNlYy9yYW1jaGFyYW4vZnJvbnRlbmQvbm9kZV9tb2R1bGVzL3JlYWN0LWxlYWZsZXQvbGliL2hvb2tzLmpzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IHVzZUxlYWZsZXRDb250ZXh0IH0gZnJvbSAnQHJlYWN0LWxlYWZsZXQvY29yZSc7XG5pbXBvcnQgeyB1c2VFZmZlY3QgfSBmcm9tICdyZWFjdCc7XG5leHBvcnQgZnVuY3Rpb24gdXNlTWFwKCkge1xuICAgIHJldHVybiB1c2VMZWFmbGV0Q29udGV4dCgpLm1hcDtcbn1cbmV4cG9ydCBmdW5jdGlvbiB1c2VNYXBFdmVudCh0eXBlLCBoYW5kbGVyKSB7XG4gICAgY29uc3QgbWFwID0gdXNlTWFwKCk7XG4gICAgdXNlRWZmZWN0KGZ1bmN0aW9uIGFkZE1hcEV2ZW50SGFuZGxlcigpIHtcbiAgICAgICAgLy8gQHRzLWlnbm9yZSBldmVudCB0eXBlXG4gICAgICAgIG1hcC5vbih0eXBlLCBoYW5kbGVyKTtcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIHJlbW92ZU1hcEV2ZW50SGFuZGxlcigpIHtcbiAgICAgICAgICAgIC8vIEB0cy1pZ25vcmUgZXZlbnQgdHlwZVxuICAgICAgICAgICAgbWFwLm9mZih0eXBlLCBoYW5kbGVyKTtcbiAgICAgICAgfTtcbiAgICB9LCBbXG4gICAgICAgIG1hcCxcbiAgICAgICAgdHlwZSxcbiAgICAgICAgaGFuZGxlclxuICAgIF0pO1xuICAgIHJldHVybiBtYXA7XG59XG5leHBvcnQgZnVuY3Rpb24gdXNlTWFwRXZlbnRzKGhhbmRsZXJzKSB7XG4gICAgY29uc3QgbWFwID0gdXNlTWFwKCk7XG4gICAgdXNlRWZmZWN0KGZ1bmN0aW9uIGFkZE1hcEV2ZW50SGFuZGxlcnMoKSB7XG4gICAgICAgIG1hcC5vbihoYW5kbGVycyk7XG4gICAgICAgIHJldHVybiBmdW5jdGlvbiByZW1vdmVNYXBFdmVudEhhbmRsZXJzKCkge1xuICAgICAgICAgICAgbWFwLm9mZihoYW5kbGVycyk7XG4gICAgICAgIH07XG4gICAgfSwgW1xuICAgICAgICBtYXAsXG4gICAgICAgIGhhbmRsZXJzXG4gICAgXSk7XG4gICAgcmV0dXJuIG1hcDtcbn1cbiJdLCJuYW1lcyI6W10sImlnbm9yZUxpc3QiOlswXSwic291cmNlUm9vdCI6IiJ9\n//# sourceURL=webpack-internal:///(ssr)/./node_modules/react-leaflet/lib/hooks.js\n");

/***/ })

};
;