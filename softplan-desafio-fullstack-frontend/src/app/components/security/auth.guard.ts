import { SharedService } from './../../services/shared.service';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot } from "@angular/router";
import { Injectable } from "@angular/core";
import { Observable } from 'rxjs';

@Injectable()
export class AuthGuard implements CanActivate {

    public shared : SharedService;
    router: any;

    constructor(){
        this.shared = SharedService.getInstance();
    }

    canActivate(
        route: ActivatedRouteSnapshot, 
        state: RouterStateSnapshot): boolean | Observable<boolean> | Promise<boolean> {
           if(this.shared.isLoggedIn()){
                return true;
           } else {
               this.router.navigate(['/login']);
               return false;
           }
    }
}