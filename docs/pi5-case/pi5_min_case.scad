// Raspberry Pi 5 Minimalistic Case
// STL-ready via OpenSCAD export
// part = "base" or "lid"

part = "base";

// --------------------
// Core dimensions
// --------------------
board_x = 85;
board_y = 56;
board_z = 3;

tol = 0.5;            // fit tolerance
wall = 2.2;
base_floor = 2.4;
lid_top = 2.2;
inner_h = 21;         // internal vertical clearance above board
corner_r = 4;

outer_x = board_x + wall*2 + tol*2;
outer_y = board_y + wall*2 + tol*2;
base_h = base_floor + board_z + inner_h*0.62;
lid_h  = lid_top + inner_h*0.38;

// Board origin inside case
board_off_x = wall + tol;
board_off_y = wall + tol;

$fn = 48;

module rounded_box(x,y,z,r){
  hull(){
    for (ix=[r, x-r], iy=[r, y-r], iz=[r, z-r])
      translate([ix,iy,iz]) sphere(r=r);
  }
}

module shell_base(){
  difference(){
    rounded_box(outer_x, outer_y, base_h, corner_r);
    translate([wall, wall, wall])
      rounded_box(outer_x-2*wall, outer_y-2*wall, base_h, max(corner_r-wall,1));
    // open top of base
    translate([-1,-1,base_h-1]) cube([outer_x+2, outer_y+2, base_h+2]);
  }
}

module shell_lid(){
  difference(){
    rounded_box(outer_x, outer_y, lid_h, corner_r);
    translate([wall, wall, 0])
      rounded_box(outer_x-2*wall, outer_y-2*wall, lid_h-wall, max(corner_r-wall,1));
  }

  // lip for slip fit
  difference(){
    translate([wall+0.25, wall+0.25, 0])
      cube([outer_x-2*(wall+0.25), outer_y-2*(wall+0.25), wall+1.2]);
    translate([wall+1.45, wall+1.45, -0.1])
      cube([outer_x-2*(wall+1.45), outer_y-2*(wall+1.45), wall+1.6]);
  }
}

module standoff(x,y,h=4.5,od=6,id=2.8){
  translate([x,y,base_floor])
  difference(){
    cylinder(h=h,d=od);
    translate([0,0,-0.2]) cylinder(h=h+0.4,d=id);
  }
}

module board_mounts(){
  // Approximate Pi 5 mount pattern (same footprint family)
  standoff(board_off_x+3.5,           board_off_y+3.5);
  standoff(board_off_x+board_x-3.5,   board_off_y+3.5);
  standoff(board_off_x+3.5,           board_off_y+board_y-3.5);
  standoff(board_off_x+board_x-3.5,   board_off_y+board_y-3.5);
}

module side_cutouts(){
  // Front (USB-C power + micro HDMI x2)
  translate([board_off_x+6, -1, base_floor+4]) cube([12, wall+2, 7]);      // USB-C PWR
  translate([board_off_x+24, -1, base_floor+4]) cube([12, wall+2, 6]);     // micro HDMI 0
  translate([board_off_x+38, -1, base_floor+4]) cube([12, wall+2, 6]);     // micro HDMI 1

  // Left side (audio jack)
  translate([-1, board_off_y+44, base_floor+4]) cube([wall+2, 10, 8]);

  // Right side (USB + ethernet cluster)
  translate([outer_x- wall -1, board_off_y+5,  base_floor+4]) cube([wall+2, 40, 15]);

  // Rear side (GPIO airflow slot zone - minimal)
  translate([board_off_x+10, outer_y-wall-1, base_floor+8]) cube([60, wall+2, 8]);
}

module vents(){
  // top ventilation slots for lid
  for(i=[0:7]){
    translate([14+i*8.5, 10, lid_h-1.2]) cube([3, outer_y-20, 2]);
  }
}

module base(){
  difference(){
    union(){
      shell_base();
      board_mounts();
    }
    side_cutouts();
  }
}

module lid(){
  difference(){
    shell_lid();
    vents();
  }
}

if (part == "base") base();
if (part == "lid")  lid();
