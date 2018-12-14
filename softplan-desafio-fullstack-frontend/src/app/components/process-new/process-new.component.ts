import { ActivatedRoute } from '@angular/router';
import { ProcessService } from './../../services/process.service';
import { Process } from './../../model/process.model';
import { Component, OnInit, ViewChild } from '@angular/core';
import { NgForm } from '@angular/forms';
import { SharedService } from 'src/app/services/shared.service';
import { ResponseApi } from 'src/app/model/response-api';

@Component({
  selector: 'app-process-new',
  templateUrl: './process-new.component.html',
  styleUrls: ['./process-new.component.css']
})
export class ProcessNewComponent implements OnInit {

  @ViewChild("form")
  form: NgForm;
  shared: SharedService;
  message: {};
  classCss: {};

  process = new Process('',0,'','',null,null,'',null);
  constructor(
    private processService: ProcessService,
    private route: ActivatedRoute
  ) { 
    this.shared = SharedService.getInstance();
  }

  ngOnInit() {
    let id : string = this.route.snapshot.params['id'];
    if(id != undefined){
      this.findById(id);
    }
  }

  findById(id: string){
    this.processService.findById(id).subscribe((responseApi: ResponseApi) =>{
      this.process = responseApi.data;
    }, err => {
      this.showMessage({
        type: 'error',
        text: err['error']['errors'][0]
      })
    });
  }

  register(){
    this.message = {};
    this.processService.create(this.process.ocurrence).subscribe((responseApi: ResponseApi) => {
      this.process = new Process('',0,'','',null,null,'',null);
      let processRet: Process = responseApi.data;
      this.form.resetForm();
      this.showMessage({
        type: 'success',
        text: `Registered Process Number ${processRet.number} successfully`
      });
    }, err => {
      this.showMessage({
        type: 'error',
        text: err['error']['errors'][0]
      });
    });
  }

  private showMessage(message: {type: string, text: string}){
    this.message = message;
    this.buildClasses(message.type);
    setTimeout(() => {
      this.message = undefined;
    }, 4000);
  }

  private buildClasses(type: string): void{
    this.classCss = {
      'alert' : true
    }
    this.classCss['alert-'+type] = true;
  }

  getFromGroupClasse(isInvalid:boolean, isDirty){
    return{
      'form-group' : true,
      'has-error' : isInvalid && isDirty,
      'has-success' : isInvalid && isDirty,
    }
  }
}
