webpackJsonp([2],{ZjJx:function(e,t,a){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var l={data:function(){return{drawer:!1,search_keyword:"",tableData:[],currentPage:1,pageSize:15,labelPosition:"left",projectID:"",vulDetail:{vid:1},loading:!0}},methods:{handleSizeChange:function(e){this.pageSize=e},handleCurrentChange:function(e){this.currentPage=e},getVulData:function(e){var t=this,a={projectID:e};this.http.projectDatail(a).then(function(e){t.tableData=e.data.data,t.loading=!1}).catch()},getCellIndex:function(e){var t=e.row,a=e.column,l=e.rowIndex,i=e.columnIndex;t.index=l,a.index=i},cellClick:function(e,t,a,l){var i=this;if(console.log(t),console.log(e.vtoken),0===t.index){var r={projectID:this.projectID,vtoken:e.vtoken};this.http.singleVulDetail(r).then(function(e){i.vulDetail=e.data.data[0],i.drawer=!0}).catch()}},setCellStyle:function(e){var t=e.row;e.column,e.rowIndex;if(2===e.columnIndex)return"Critical"===t.risk?{color:"red"}:"Low"===t.risk?{color:"green"}:"High"===t.risk?{color:"orange"}:{color:"yellow"}},filterTag:function(e,t){return t.risk===e},clearFilter:function(){this.$refs.filterTable.clearFilter()},comeback:function(){this.$router.push({path:"/projectDatail"})},onSubmit:function(){this.$message({message:"恭喜发财",type:"success"})}},mounted:function(){var e=this.$route.query.projectID;this.projectID=e,this.getVulData(e)},computed:{prop:function(){return{subfield:!1,defaultOpen:"preview",editable:!1,toolbarsFlag:!1,scrollStyle:!1,boxShadow:!0}}},created:function(){},updated:function(){}},i={render:function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("div",{attrs:{id:"vdetail"}},[a("div",{staticStyle:{margin:"10px 0 5px 0"}},[a("el-button",{attrs:{type:"primary",size:"mini"},on:{click:e.comeback}},[e._v("返回")]),e._v(" "),a("el-input",{staticClass:"input-with-select",staticStyle:{float:"right",width:"50%"},attrs:{placeholder:"请输入搜索关键词",size:"mini"},model:{value:e.search_keyword,callback:function(t){e.search_keyword=t},expression:"search_keyword"}},[a("el-button",{attrs:{slot:"append",icon:"el-icon-search",type:"primary"},slot:"append"})],1)],1),e._v(" "),a("el-table",{directives:[{name:"loading",rawName:"v-loading",value:e.loading,expression:"loading"}],staticStyle:{width:"100%"},attrs:{data:e.tableData.slice((e.currentPage-1)*e.pageSize,e.currentPage*e.pageSize),border:"",size:"mini","cell-class-name":e.getCellIndex,"cell-style":e.setCellStyle},on:{"cell-click":e.cellClick}},[a("el-table-column",{attrs:{prop:"id",label:"详情",width:"50",align:"center"},scopedSlots:e._u([{key:"default",fn:function(e){return[a("i",{staticClass:"el-icon-view handleData"})]}}])}),e._v(" "),a("el-table-column",{attrs:{prop:"vid",label:"ID",width:"50",align:"center"}}),e._v(" "),e._e(),e._v(" "),a("el-table-column",{attrs:{prop:"risk",label:"风险等级",align:"center",width:"120",filters:[{text:"严重",value:"Critical"},{text:"高危",value:"High"},{text:"中危",value:"Medium"},{text:"低危",value:"Low"}],"filter-method":e.filterTag,sortable:""}}),e._v(" "),a("el-table-column",{attrs:{prop:"title",label:"漏洞类型",align:"center",width:"400"}}),e._v(" "),a("el-table-column",{attrs:{prop:"FilePath",label:"漏洞所在文件",align:"",width:""}}),e._v(" "),a("el-table-column",{attrs:{prop:"FileName",label:"文件名",align:"center",width:"200"}}),e._v(" "),a("el-table-column",{attrs:{prop:"LineStart",label:"影响行",align:"center",width:"100"}}),e._v(" "),a("el-table-column",{attrs:{prop:"extend",label:"文件类型",align:"center",width:"100"}}),e._v(" "),a("el-table-column",{attrs:{prop:"time",label:"扫描时间",align:"center",width:"150"}})],1),e._v(" "),a("div",{attrs:{id:"fenye"}},[a("el-pagination",{attrs:{"current-page":e.currentPage,"page-sizes":[15,20,30,50,100],"page-size":e.pageSize,layout:"total, sizes, prev, pager, next, jumper",total:e.tableData.length},on:{"size-change":e.handleSizeChange,"current-change":e.handleCurrentChange}})],1),e._v(" "),a("el-drawer",{attrs:{title:"我是标题",visible:e.drawer,"with-header":!1,size:"55%",modal:!0},on:{"update:visible":function(t){e.drawer=t}}},[a("div",{attrs:{id:"needDrawer"}},[a("div",{staticStyle:{margin:"20px"}},[a("div",{staticClass:"vlabel"},[e._v("漏洞id:")]),e._v(" "),a("div",[e._v(e._s(e.vulDetail.vtoken))]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("扫描时间:")]),e._v(" "),a("div",[e._v(e._s(e.vulDetail.time))]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("漏洞名称:")]),e._v(" "),a("div",[e._v(e._s(e.vulDetail.title))]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("漏洞风险:")]),e._v(" "),a("div",[e._v(e._s(e.vulDetail.risk))]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("漏洞原因:")]),e._v(" "),a("div",[e._v(e._s(e.vulDetail.Abstract))]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("文件名:")]),e._v(" "),a("div",[e._v(e._s(e.vulDetail.FileName))]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("影响行:")]),e._v(" "),a("div",[e._v(e._s(e.vulDetail.LineStart))]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("影响行的代码:")]),e._v(" "),a("div",{directives:[{name:"highlight",rawName:"v-highlight"}]},[a("pre",{directives:[{name:"highlight",rawName:"v-highlight"}]},[a("code",{domProps:{innerHTML:e._s(e.vulDetail.Snippet)}})])]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("后缀名:")]),e._v(" "),a("div",[e._v(e._s(e.vulDetail.extend))]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("文件位置:")]),e._v(" "),a("div",[e._v(e._s(e.vulDetail.FilePath))]),e._v(" "),a("div",{staticClass:"vlabel"},[e._v("完整代码:")]),e._v(" "),a("div",{directives:[{name:"highlight",rawName:"v-highlight"}]},[a("pre",{directives:[{name:"highlight",rawName:"v-highlight"}]},[a("code",{domProps:{innerHTML:e._s(e.vulDetail.full_code)}})])])])])])],1)},staticRenderFns:[]};var r=a("VU/8")(l,i,!1,function(e){a("k63Q")},"data-v-fa9344c8",null);t.default=r.exports},k63Q:function(e,t){}});
//# sourceMappingURL=2.583988beac6c879b3e42.js.map