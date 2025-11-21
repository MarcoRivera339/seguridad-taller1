import { Routes } from '@angular/router';
import { CifradoSimetricoComponent } from './pages/cifrado-simetrico/cifrado-simetrico.component';
import { CifradoAsimetricoComponent } from './pages/cifrado-asimetrico/cifrado-asimetrico.component';

export const routes: Routes = [
    { path: 'simetrico', component: CifradoSimetricoComponent },
    { path: 'asimetrico', component: CifradoAsimetricoComponent },
    { path: '**', redirectTo: '' }
];
